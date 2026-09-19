#!/usr/bin/env bash
set -uo pipefail

umask 077

AUDIT_ROOT="/audit"
RUNTIME_ROOT="$AUDIT_ROOT/runtime"
WORK_ROOT="$RUNTIME_ROOT/work"
RESULT_ROOT="$RUNTIME_ROOT/results"
OUTPUT_ROOT="$RUNTIME_ROOT/output"
DEPS_ROOT="$AUDIT_ROOT/volume/deps"
PASS_COUNT=0
FAIL_COUNT=0

say() {
  printf '\n=== %s ===\n' "$*"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$*" >&2
}

die() {
  printf 'release-audit container: %s\n' "$*" >&2
  exit 2
}

run_check() {
  local label="$1"
  shift

  say "$label"
  if "$@"; then
    pass "$label"
    return 0
  fi

  fail "$label"
  return 1
}

check_offline_exec_scratch() {
  local probe
  local status

  [[ "${TMPDIR:-}" == /audit/exec-tmp && -d "$TMPDIR" && ! -L "$TMPDIR" ]] || {
    printf 'offline executable scratch is unavailable: %s\n' \
      "${TMPDIR:-<unset>}" >&2
    return 1
  }
  probe="$TMPDIR/notty-release-audit-exec-probe"
  printf '#!/bin/sh\nexit 0\n' >"$probe" || return 1
  chmod 0700 "$probe" || return 1
  "$probe"
  status=$?
  rm -f -- "$probe"
  return "$status"
}

compile_collector_loader() {
  local component="$1"
  local compile_status=0
  local cleanup_status=0

  make -C "$component" CLANG=clang-14 loader || compile_status=$?
  make -C "$component" clean || cleanup_status=$?
  (( compile_status == 0 && cleanup_status == 0 ))
}

assert_container_boundary() {
  local effective_caps

  [[ "${DOCKER_CONTAINER:-}" == "1" ]] ||
    die 'refusing to run npm: DOCKER_CONTAINER=1 is not set'
  [[ -f /.dockerenv ]] ||
    die 'refusing to run npm outside Docker'
  [[ "$(id -u)" != "0" ]] ||
    die 'refusing to run npm as root'

  effective_caps="$(awk '$1 == "CapEff:" { print $2 }' /proc/self/status)"
  [[ "$effective_caps" == "0000000000000000" ]] ||
    die "effective Linux capabilities are not empty: $effective_caps"
  [[ "${NPM_CONFIG_USERCONFIG:-}" == "/dev/null" ]] ||
    die 'NPM_CONFIG_USERCONFIG must be /dev/null'
  [[ "${HOME:-}" == "$RUNTIME_ROOT/home" ]] ||
    die "unexpected audit HOME: ${HOME:-<unset>}"

  mkdir -p \
    "$RUNTIME_ROOT/home" \
    "$RUNTIME_ROOT/npm-cache" \
    "$WORK_ROOT" \
    "$RESULT_ROOT" \
    "$OUTPUT_ROOT"
}

print_runtime_identity() {
  say 'Audit runtime identity'
  printf 'uid=%s gid=%s\n' "$(id -u)" "$(id -g)"
  printf 'node=%s\n' "$(node --version)"
  printf 'npm=%s\n' "$(npm --version)"
  printf 'network_mode=%s\n' "${RELEASE_AUDIT_NETWORK_MODE:-unknown}"
}

copy_manifests() {
  [[ -f /input/package.json ]] || die 'missing /input/package.json'
  [[ -f /input/package-lock.json ]] || die 'missing /input/package-lock.json'

  cp /input/package.json "$1/package.json"
  cp /input/package-lock.json "$1/package-lock.json"
}

check_lock_sources() {
  node --input-type=module - /input/package-lock.json <<'NODE'
import fs from 'node:fs';

const lock = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const errors = [];
for (const [packagePath, entry] of Object.entries(lock.packages ?? {})) {
  if (!packagePath || entry.link === true) continue;
  if (typeof entry.resolved !== 'string' ||
      !entry.resolved.startsWith('https://registry.npmjs.org/')) {
    errors.push(`${packagePath}: unapproved resolved URL ${entry.resolved ?? '<missing>'}`);
  }
  if (typeof entry.integrity !== 'string' || !entry.integrity.startsWith('sha512-')) {
    errors.push(`${packagePath}: missing sha512 integrity`);
  }
}

if (errors.length) {
  for (const error of errors.slice(0, 50)) console.error(`lockfile: ${error}`);
  if (errors.length > 50) console.error(`lockfile: ${errors.length - 50} more errors`);
  process.exit(1);
}

console.log('lockfile sources: HTTPS registry.npmjs.org with sha512 integrity');
NODE
}

check_metadata() {
  node --input-type=module - "$WORK_ROOT" <<'NODE'
import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2];
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const errors = [];

if (!pkg.name || !pkg.version) {
  errors.push('package.json must contain non-empty name and version fields');
}
if (lock.name !== pkg.name || lock.version !== pkg.version) {
  errors.push(
    `package-lock root ${lock.name}@${lock.version} does not match ` +
    `package.json ${pkg.name}@${pkg.version}`
  );
}
const lockRoot = lock.packages?.[''];
if (!lockRoot || lockRoot.name !== pkg.name || lockRoot.version !== pkg.version) {
  errors.push('package-lock packages[""] metadata does not match package.json');
}
if (pkg.private !== true && !pkg.publishConfig) {
  errors.push(
    'package is publishable but has no reviewed publishConfig; set private=true ' +
    'when npm publication is not intended'
  );
}

console.log(JSON.stringify({
  name: pkg.name,
  version: pkg.version,
  license: pkg.license ?? null,
  private: pkg.private === true
}, null, 2));

if (errors.length) {
  for (const error of errors) console.error(`metadata: ${error}`);
  process.exit(1);
}
NODE
}

check_release_files() {
  local required
  local missing=0

  for required in \
    LICENSE \
    THIRD_PARTY_NOTICES.md \
    SECURITY.md \
    CONTRIBUTING.md \
    CHANGELOG.md
  do
    if [[ ! -s "$WORK_ROOT/$required" ]]; then
      printf 'missing required release file: %s\n' "$required" >&2
      missing=1
    fi
  done

  if ! compgen -G "$WORK_ROOT/.github/workflows/*" >/dev/null; then
    printf 'missing checked-in CI workflow under .github/workflows/\n' >&2
    missing=1
  fi

  return "$missing"
}

inspect_pack_json() {
  local json_path="$1"
  local context="$2"

  node --input-type=module - "$json_path" "$context" "$WORK_ROOT" <<'NODE'
import fs from 'node:fs';
import path from 'node:path';

const [jsonPath, context, workRoot] = process.argv.slice(2);
let parsed;
try {
  parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
} catch (error) {
  console.error(`${context}: invalid npm pack JSON: ${error.message}`);
  process.exit(1);
}

const pack = Array.isArray(parsed) ? parsed[0] : parsed;
if (!pack || !Array.isArray(pack.files)) {
  console.error(`${context}: npm pack JSON has no file inventory`);
  process.exit(1);
}

const forbiddenPatterns = [
  /^\.release-audit\//,
  /^\.nosh-guard-host-bundles\//,
  /^\.notty-art-runs\//,
  /^\.notty\/collab-resume/,
  /^agents\/(?:active|history|intent|jobs|locks|logs|msgs|runs)\//,
  /^collab\/intragent\/channels\//,
  /^collab\/intragent\/managed_agents\.json$/,
  /^collab\/intragent\/message_feedback\.jsonl$/,
  /(^|\/)\.env(?:\.|$)/,
  /(^|\/)(?:\.npmrc|auth\.json|credentials?(?:\.[^/]*)?|tokens?(?:\.[^/]*)?)$/i,
  /(^|\/)(?:id_rsa|id_ed25519)(?:\.pub)?$/,
  /(^|\/)(?:logs?|cache)\//,
  /(^|\/)(?:node_modules|\.next)\//,
  /(?:^|\/)(?:npm-debug\.log|[^/]+\.(?:log|swp|swo))$/,
  /^start_oauth\.sh$/,
  /^art\/acid(?:\.orig)?\//,
  /^ansi\/(?:ansi-block-ghosts\.ans|iniquity-ghosts3\.asc|screenshot\.jpg)$/,
  /^ansi\/art\/iniquity-ghosts/,
  /^ansi\/AsciiEffect\.js$/,
  /^ansi\/dd\/install-with-pipx\.sh$/
];

const filePaths = pack.files.map((entry) => entry.path);
const forbidden = filePaths.filter((file) =>
  forbiddenPatterns.some((pattern) => pattern.test(file))
);
const requiredBuildProfilePaths = [
  'build-nosh.sh',
  'Dockerfile.guard',
  'Dockerfile.nosh-guard-host-bundle',
  'config/nosh-guard/schemas/http-content-manifest.schema.json',
  'config/nosh-guard/schemas/http-exchange-evidence.schema.json',
  'docs/nosh-http-capture-contract.md',
  'lib/authState.js',
  'lib/guardGatewayAuth.js',
  'lib/guardd/auth-reset-worker.js',
  'lib/guardd/auth-state.js',
  'bpf/nosh_build/Makefile',
  'bpf/nosh_build/README.md',
  'bpf/nosh_build/adapter.example.json',
  'bpf/nosh_build/include/nosh_build.h',
  'bpf/nosh_build/loader/nosh_build_loader.c',
  'bpf/nosh_build/nosh_build.bpf.c',
  'bpf/nosh_build/schema/nosh-build-capabilities.schema.json',
  'bpf/nosh_build/schema/nosh-build-control.schema.json',
  'bpf/nosh_build/schema/nosh-build-event.schema.json',
  'bpf/nosh_build/schema/nosh-build-file-summary.schema.json',
  'bpf/nosh_build/schema/nosh-build-stats.schema.json',
  'bpf/nosh_build/schema/nosh-build-syscall-summary.schema.json',
  'bpf/nosh_build/tests/nosh-build-static.test.cjs',
  'bpf/nosh_url/Makefile',
  'bpf/nosh_url/README.md',
  'bpf/nosh_url/include/nosh_url.h',
  'bpf/nosh_url/loader/nosh_url_loader.c',
  'bpf/nosh_url/loader/url_sanitizer.c',
  'bpf/nosh_url/loader/url_sanitizer.h',
  'bpf/nosh_url/nosh_url.bpf.c',
  'bpf/nosh_url/schema/nosh-url-event.schema.json',
  'bpf/nosh_url/schema/nosh-url-stats.schema.json',
  'bpf/nosh_url/schema/nosh-url-status.schema.json',
  'bpf/nosh_url/tests/include/bpf/bpf.h',
  'bpf/nosh_url/tests/include/bpf/libbpf.h',
  'bpf/nosh_url/tests/include/nosh_url.skel.h',
  'bpf/nosh_url/tests/loader_stubs.c',
  'bpf/nosh_url/tests/static.sh',
  'bpf/nosh_url/tests/url_sanitizer_test.c',
  'bpf/nosh_l4/schema/nosh-l4-flow-summary.schema.json',
  'bpf/nosh_egress/Makefile',
  'bpf/nosh_egress/README.md',
  'bpf/nosh_egress/include/nosh_egress.h',
  'bpf/nosh_egress/loader/nosh_egress_loader.c',
  'bpf/nosh_egress/nosh_egress.bpf.c',
  'bpf/nosh_egress/tests/static.sh',
  'bin/nosh-gateway',
  'config/nosh-build/adapters.json',
  'config/nosh-build/versions.json',
  'deploy/host/nosh-guard',
  'deploy/host/nosh-guard-fail-closed',
  'deploy/host/nosh-guard-tetragon-verify',
  'deploy/host/nosh-guardd',
  'deploy/systemd/nosh-guard-bpffs.service',
  'deploy/systemd/nosh-guardd.service',
  'lib/guardd/http-capture-manager.js',
  'lib/guardd/http-content-store.js',
  'lib/guardd/http-evidence.js',
  'scripts/nosh-mitmproxy-addon.py',
  'scripts/nosh-mitmproxy-capture.sh',
  'tests/nosh-http-capture-manager.test.cjs',
  'tests/nosh-http-evidence.test.cjs',
  'tests/nosh-guard-auth-reset.test.cjs',
  'tests/nosh-l7-proxy-compiler.test.cjs',
  'config/nosh-guard/build-profile-contract.json',
  'config/nosh-guard/schemas/build-evidence-manifest.schema.json',
  'config/nosh-guard/schemas/build-network-candidate.schema.json',
  'config/nosh-guard/schemas/build-network-policy-draft.schema.json',
  'config/nosh-guard/schemas/build-portable-bundle.schema.json',
  'config/nosh-guard/schemas/build-profile-candidate.schema.json',
  'config/nosh-guard/schemas/ebpf-deployment-trust.schema.json',
  'config/nosh-guard/schemas/review/build-http-observations.schema.json',
  'config/nosh-guard/schemas/review/common.schema.json',
  'config/nosh-guard/schemas/review/dsse-envelope.schema.json',
  'config/nosh-guard/schemas/review/deployment-grant-statement.schema.json',
  'config/nosh-guard/schemas/review/ebpf-egress-policy.schema.json',
  'config/nosh-guard/schemas/review/ebpf-target-context.schema.json',
  'config/nosh-guard/schemas/review/portable-gateway-target-context.schema.json',
  'config/nosh-guard/schemas/review/gateway-grant-statement.schema.json',
  'config/nosh-guard/schemas/review/graph-record.schema.json',
  'config/nosh-guard/schemas/review/graph-view-state.schema.json',
  'config/nosh-guard/schemas/review/policy-decision-set.schema.json',
  'config/nosh-guard/schemas/review/policy-ir.schema.json',
  'config/nosh-guard/schemas/review/policy-leaf-bundle.schema.json',
  'config/nosh-guard/schemas/review/portable-gateway-policy.schema.json',
  'config/nosh-guard/schemas/review/review-approval-statement.schema.json',
  'config/nosh-guard/schemas/review/review-bundle.schema.json',
  'config/nosh-guard/schemas/review/semantic-graph-delta.schema.json',
  'config/nosh-guard/schemas/review/semantic-graph.schema.json',
  'config/nosh-guard/schemas/review/target-review-set.schema.json',
  'config/nosh-review/tools.json',
  'config/nosh-gateway/trust.schema.json',
  'deploy/host/nosh-gateway',
  'docs/nosh-gateway.md',
  'docs/nosh-build-profiling.md',
  'docs/nosh-policy-review.md',
  'lib/guard/review/approval-service.js',
  'lib/guard/review/build-adapter.js',
  'lib/guard/review/bundle-store.js',
  'lib/guard/review/cli.js',
  'lib/guard/review/constants.js',
  'lib/guard/review/documents.js',
  'lib/guard/review/deployment-cli.js',
  'lib/guard/review/gateway-cli.js',
  'lib/guard/review/gateway-host.js',
  'lib/guard/review/grant-service.js',
  'lib/guard/review/ids.js',
  'lib/guard/review/index.js',
  'lib/guard/review/io.js',
  'lib/guard/review/jcs.js',
  'lib/guard/review/leaf-store.js',
  'lib/guard/review/policy-cli.js',
  'lib/guard/review/policy-compilers.js',
  'lib/guard/review/privacy.js',
  'lib/guard/review/projection-service.js',
  'lib/guard/review/records.js',
  'lib/guard/review/review-service.js',
  'lib/guard/review/runtime-adapter.js',
  'lib/guard/review/sbom.js',
  'lib/guard/review/signing.js',
  'lib/guard/review/streams.js',
  'lib/guard/review/validation.js',
  'lib/guardd/build-orchestrator.js',
  'lib/guardd/install-layout.js',
  'lib/guardd/build-profile-artifacts.js',
  'lib/guardd/build-profile-mirror.js',
  'lib/guardd/build-profile-report.js',
  'lib/guardd/build-profile-store.js',
  'lib/guardd/build-session-service.js',
  'lib/guardd/ebpf-activation-store.js',
  'lib/guardd/enforcement-backend.js',
  'policy-review/.dockerignore',
  'policy-review/components/policy-review/PolicyReview.module.css',
  'policy-review/components/policy-review/PolicyReviewCanvas.js',
  'policy-review/components/policy-review/PolicyReviewPage.js',
  'policy-review/components/policy-review/PolicyReviewTimeline.js',
  'policy-review/Dockerfile',
  'policy-review/modules/__tests__/semanticGraph.spec.js',
  'policy-review/modules/__tests__/iptablesExport.spec.js',
  'policy-review/modules/__tests__/proposalSelectionState.spec.js',
  'policy-review/modules/__tests__/runtimeAttestation.spec.js',
  'policy-review/modules/__tests__/timelineState.spec.js',
  'policy-review/modules/__tests__/timelineProjection.spec.js',
  'policy-review/modules/policy-review/proposalDerivation.js',
  'policy-review/modules/policy-review/iptablesExport.js',
  'policy-review/modules/policy-review/reviewStore.js',
  'policy-review/modules/policy-review/runtimeAttestation.js',
  'policy-review/modules/policy-review/semanticGraph.js',
  'policy-review/modules/policy-review/timelineProjection.js',
  'policy-review/next.config.js',
  'policy-review/package-lock.json',
  'policy-review/package.json',
  'policy-review/pages/_app.js',
  'policy-review/pages/api/policy-review-attestation.js',
  'policy-review/pages/api/policy-review-decision-set.js',
  'policy-review/pages/index.js',
  'policy-review/pages/policy-review.js',
  'policy-review/README.md',
  'policy-review/styles/globals.css',
  'policy-review/tests/dev-runtime.test.cjs',
  'policy-review/tests/next-config.test.cjs',
  'policy-review/tests/runtime-attestation-api.test.cjs',
  'policy-review/tests/decision-set-api.test.cjs',
  'policy-review/tests/selected-iptables-export-ui.test.cjs',
  'profile-build-and-review.sh',
  'profile-build-and-run.sh',
  'reset-nosh-guard.sh',
  'setup-nosh.sh',
  'scripts/build-nosh-guard-host-bundle.sh',
  'scripts/build-nosh-guard-host-bundle-container.sh',
  'scripts/ensure-nosh-guard-bpffs.sh',
  'scripts/install-nosh-guard-host-bundle.sh',
  'scripts/nosh-egress-containment-probe.mjs',
  'scripts/nosh-guard-doctor.sh',
  'scripts/nosh-gateway.mjs',
  'scripts/render-nosh-guard-install.mjs',
  'scripts/run-nosh-guard-host-bundle-container.sh',
  'scripts/verify-nosh-guard-host-install.sh',
  'tests/nosh-build-installation.test.cjs',
  'tests/build-nosh-launcher.test.cjs',
  'tests/nosh-review-graph-server.test.cjs',
  'tests/nosh-semantic-review-core.test.cjs',
  'tests/nosh-policy-review-integration.test.cjs',
  'tests/nosh-policy-review-ui.test.cjs',
  'tests/nosh-gateway-host.test.cjs',
  'tests/nosh-guard-host-reset.test.cjs',
  'tests/profile-build-and-review.test.cjs',
  'tests/profile-build-and-run.test.cjs',
  'tests/nosh-guard-host-bundle.test.cjs',
  'tests/nosh-guard-install-layout.test.cjs',
  'tests/nosh-guard-install-renderer.test.cjs',
  'tests/nosh-egress-containment-probe.test.cjs',
  'tests/build-network-deny.test.cjs',
  'tests/reviewed-policy-enforcement.test.cjs',
  'tests/nosh-setup.test.cjs'
];
const missingBuildProfilePaths = requiredBuildProfilePaths.filter(
  (required) => !filePaths.includes(required)
);

const pkg = JSON.parse(fs.readFileSync(path.join(workRoot, 'package.json'), 'utf8'));
const inventory = new Map(pack.files.map((entry) => [entry.path, entry]));
const badBins = [];
for (const [name, target] of Object.entries(pkg.bin ?? {})) {
  const normalized = String(target).replace(/^\.\//, '');
  const entry = inventory.get(normalized);
  const sourcePath = path.join(workRoot, normalized);
  if (!entry) {
    badBins.push(`${name}: missing ${normalized} from package`);
    continue;
  }
  if (!fs.existsSync(sourcePath) || (fs.statSync(sourcePath).mode & 0o111) === 0) {
    badBins.push(`${name}: ${normalized} is not executable in source`);
  }
  if (typeof entry.mode === 'number' && (entry.mode & 0o111) === 0) {
    badBins.push(`${name}: ${normalized} is not executable in package metadata`);
  }
}

console.log(JSON.stringify({
  context,
  filename: pack.filename ?? null,
  packageFiles: pack.files.length,
  unpackedSize: pack.unpackedSize ?? null,
  forbiddenPaths: forbidden,
  missingBuildProfilePaths,
  invalidBins: badBins
}, null, 2));

if (forbidden.length || missingBuildProfilePaths.length || badBins.length) {
  process.exit(1);
}
NODE
}

run_acquire() {
  local input_lock_hash
  local acquired_lock_hash
  local status

  say 'Manifest-only dependency acquisition'
  run_check 'Lockfile source and integrity policy' check_lock_sources || return 1
  input_lock_hash="$(sha256sum /input/package-lock.json | awk '{ print $1 }')"
  rm -rf "$DEPS_ROOT/node_modules"
  copy_manifests "$DEPS_ROOT"
  cd "$DEPS_ROOT" || die "cannot enter $DEPS_ROOT"

  npm_config_audit=false \
  npm_config_fund=false \
  npm_config_update_notifier=false \
    npm ci --ignore-scripts --legacy-peer-deps
  status=$?

  if (( status != 0 )); then
    fail 'npm ci --ignore-scripts'
    return 1
  fi
  [[ -d "$DEPS_ROOT/node_modules" ]] || {
    fail 'npm ci completed without node_modules'
    return 1
  }

  acquired_lock_hash="$(sha256sum "$DEPS_ROOT/package-lock.json" | awk '{ print $1 }')"
  if [[ "$input_lock_hash" != "$acquired_lock_hash" ]]; then
    fail 'npm ci changed the package lockfile copy'
    return 1
  fi

  pass 'npm ci --ignore-scripts completed in the networked manifest-only container'
  return 0
}

run_advisories() {
  local audit_json="$RESULT_ROOT/npm-audit.json"
  local npm_status
  local parse_status

  copy_manifests "$WORK_ROOT"
  cd "$WORK_ROOT" || die "cannot enter $WORK_ROOT"

  say 'Production dependency advisories'
  npm audit --omit=dev --json >"$audit_json"
  npm_status=$?

  node --input-type=module - "$audit_json" "$npm_status" <<'NODE'
import fs from 'node:fs';

const [auditPath, rawStatus] = process.argv.slice(2);
const npmStatus = Number(rawStatus);
let report;
try {
  report = JSON.parse(fs.readFileSync(auditPath, 'utf8'));
} catch (error) {
  console.error(`invalid npm audit JSON: ${error.message}`);
  process.exit(1);
}

const counts = report.metadata?.vulnerabilities;
if (!counts || typeof counts.total !== 'number') {
  const message = report.error?.summary ?? report.error?.detail ?? 'missing vulnerability totals';
  console.error(`npm audit did not return a vulnerability report: ${message}`);
  process.exit(1);
}

const findings = Object.entries(report.vulnerabilities ?? {}).map(([name, item]) => ({
  name,
  severity: item.severity ?? 'unknown',
  direct: item.isDirect === true
}));
console.log(JSON.stringify({ npmStatus, vulnerabilities: counts, findings }, null, 2));
if (npmStatus !== 0 || counts.total !== 0) process.exit(1);
NODE
  parse_status=$?

  if (( parse_status == 0 )); then
    pass 'npm audit reports zero known production vulnerabilities'
    return 0
  fi

  fail 'npm audit reports vulnerabilities or an unusable advisory response'
  return 1
}

run_verify() {
  local dry_pack_json="$RESULT_ROOT/npm-pack-dry-run.json"
  local pack_json="$RESULT_ROOT/npm-pack.json"
  local source_lock_hash
  local deps_lock_hash
  local dependency_entry
  local dependency_entries=()

  shopt -s dotglob nullglob
  dependency_entries=("$DEPS_ROOT"/*)
  (( ${#dependency_entries[@]} == 3 )) ||
    die 'dependency volume contains unexpected top-level entries'
  for dependency_entry in "${dependency_entries[@]}"; do
    case "${dependency_entry##*/}" in
      node_modules|package.json|package-lock.json) ;;
      *) die "dependency volume contains unexpected entry: $dependency_entry" ;;
    esac
  done

  [[ -f "$DEPS_ROOT/package.json" && ! -L "$DEPS_ROOT/package.json" &&
     -f "$DEPS_ROOT/package-lock.json" && ! -L "$DEPS_ROOT/package-lock.json" ]] ||
    die 'dependency volume manifests are not regular files'
  deps_lock_hash="$(sha256sum "$DEPS_ROOT/package-lock.json" | awk '{ print $1 }')"
  [[ -d "$DEPS_ROOT/node_modules" && ! -L "$DEPS_ROOT/node_modules" ]] ||
    die 'dependency volume has no regular node_modules directory; acquisition did not complete'

  # After acquisition, the dependency volume is remounted into this no-network
  # verifier. Extract the source beside its real node_modules directory so tests
  # can execute files and Turbopack never has to follow an out-of-project
  # dependency symlink.
  WORK_ROOT="$DEPS_ROOT"
  say 'Extract clean Git snapshot'
  tar \
    --extract \
    --file - \
    --directory "$WORK_ROOT" \
    --no-same-owner \
    --no-same-permissions || die 'could not extract the source archive from stdin'

  source_lock_hash="$(sha256sum "$WORK_ROOT/package-lock.json" | awk '{ print $1 }')"
  [[ "$source_lock_hash" == "$deps_lock_hash" ]] ||
    die 'dependency volume lockfile does not match the clean source snapshot'
  [[ -d "$WORK_ROOT/node_modules" && ! -L "$WORK_ROOT/node_modules" ]] ||
    die 'source extraction replaced the acquired node_modules directory'
  cd "$WORK_ROOT" || die "cannot enter $WORK_ROOT"

  run_check 'Offline executable test scratch' check_offline_exec_scratch || return 1

  run_check 'Release metadata agrees' check_metadata || true
  run_check 'Required release files and CI exist' check_release_files || true
  run_check \
    'Explicit node-pty native rebuild (offline)' \
    env npm_config_nodedir=/usr/local \
      npm rebuild node-pty --unsafe-perm --offline || true
  run_check 'Deterministic test suite (offline)' npm test || true
  run_check \
    'Build eBPF collector static contract (offline)' \
    make -C bpf/nosh_build test || true
  run_check \
    'Optional URL eBPF collector static contract (offline)' \
    make -C bpf/nosh_url test || true
  run_check \
    'L4 eBPF collector static contract (offline)' \
    make -C bpf/nosh_l4 test || true
  run_check \
    'Scoped egress eBPF static contract (offline)' \
    make -C bpf/nosh_egress test || true
  run_check \
    'Build eBPF collector CO-RE compile (offline)' \
    compile_collector_loader bpf/nosh_build || true
  run_check \
    'Optional URL eBPF collector CO-RE compile (offline)' \
    compile_collector_loader bpf/nosh_url || true
  run_check \
    'L4 eBPF collector CO-RE compile (offline)' \
    compile_collector_loader bpf/nosh_l4 || true
  run_check \
    'Scoped egress eBPF CO-RE compile (offline)' \
    compile_collector_loader bpf/nosh_egress || true
  run_check 'Production build (offline)' npm run build || true

  say 'Dry-run package inventory (offline, scripts disabled)'
  if npm pack --dry-run --json --ignore-scripts >"$dry_pack_json"; then
    if inspect_pack_json "$dry_pack_json" 'clean-snapshot-dry-run'; then
      pass 'clean snapshot package dry-run contains no forbidden paths'
    else
      fail 'clean snapshot package dry-run contains forbidden or invalid paths'
    fi
  else
    fail 'npm pack --dry-run failed'
  fi

  say 'Actual package artifact (offline, scripts disabled)'
  if npm pack \
    --json \
    --ignore-scripts \
    --pack-destination "$OUTPUT_ROOT" >"$pack_json"
  then
    if inspect_pack_json "$pack_json" 'clean-snapshot-artifact'; then
      local tarball
      tarball="$(node --input-type=module - "$pack_json" "$OUTPUT_ROOT" <<'NODE'
import fs from 'node:fs';
import path from 'node:path';
const [reportPath, outputRoot] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
const pack = Array.isArray(report) ? report[0] : report;
const filename = path.basename(pack.filename);
const resolved = path.resolve(outputRoot, filename);
if (!resolved.startsWith(`${path.resolve(outputRoot)}${path.sep}`)) process.exit(1);
console.log(resolved);
NODE
)"
      if [[ -f "$tarball" ]]; then
        printf 'package_sha256=%s\n' "$(sha256sum "$tarball" | awk '{ print $1 }')"
        pass 'actual package artifact created and inspected inside the container'
      else
        fail 'npm pack did not create the reported tarball'
      fi
    else
      fail 'actual package artifact contains forbidden or invalid paths'
    fi
  else
    fail 'npm pack failed'
  fi

  say 'Offline verification summary'
  printf 'passes=%d failures=%d\n' "$PASS_COUNT" "$FAIL_COUNT"
  (( FAIL_COUNT == 0 ))
}

run_inventory() {
  local inventory_json="$RESULT_ROOT/npm-pack-full-checkout.json"

  tar \
    --extract \
    --file - \
    --directory "$WORK_ROOT" \
    --no-same-owner \
    --no-same-permissions || die 'could not extract the full-checkout archive from stdin'
  cd "$WORK_ROOT" || die "cannot enter $WORK_ROOT"

  say 'Full-checkout package leak inventory (offline, scripts disabled)'
  if ! npm pack --dry-run --json --ignore-scripts >"$inventory_json"; then
    fail 'full-checkout npm pack --dry-run failed'
    return 1
  fi
  if inspect_pack_json "$inventory_json" 'full-checkout-dry-run'; then
    pass 'full checkout package inventory contains no forbidden paths'
    return 0
  fi

  fail 'full checkout package inventory contains forbidden or invalid paths'
  return 1
}

usage() {
  cat <<'EOF'
Usage: release-audit-container <acquire|advisories|verify|inventory>

This helper is internal. It refuses to execute npm unless it is running as a
non-root, capability-free process inside the release audit container.
EOF
}

main() {
  local mode="${1:-}"

  case "$mode" in
    -h|--help)
      usage
      return 0
      ;;
    acquire|advisories|verify|inventory)
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac

  assert_container_boundary
  print_runtime_identity

  case "$mode" in
    acquire) run_acquire ;;
    advisories) run_advisories ;;
    verify) run_verify ;;
    inventory) run_inventory ;;
  esac
}

main "$@"
