#!/usr/bin/env bash
set -euo pipefail

umask 077

RUNTIME_ROOT=/lock/runtime
WORK_ROOT="$RUNTIME_ROOT/work"
PACKAGE_PATH="$WORK_ROOT/package.json"
LOCK_PATH="$WORK_ROOT/package-lock.json"
AUDIT_PATH="$RUNTIME_ROOT/npm-audit.json"
EXPECTED_NODE_VERSION=v24.18.0
EXPECTED_NPM_VERSION=11.16.0

die() {
  printf 'package-lock container: %s\n' "$*" >&2
  exit 2
}

log() {
  printf 'package-lock container: %s\n' "$*" >&2
}

assert_container_boundary() {
  local mode="$1"
  local key
  local status_key
  local status_value
  local effective_caps=""

  [[ "${DOCKER_CONTAINER:-}" == 1 ]] ||
    die 'refusing to run npm: DOCKER_CONTAINER=1 is not set'
  [[ -f /.dockerenv ]] || die 'refusing to run npm outside Docker'
  [[ "$(id -u)" != 0 ]] || die 'refusing to run npm as root'

  while read -r status_key status_value _; do
    if [[ "$status_key" == CapEff: ]]; then
      effective_caps="$status_value"
      break
    fi
  done </proc/self/status
  [[ "$effective_caps" == 0000000000000000 ]] ||
    die "effective Linux capabilities are not empty: ${effective_caps:-unavailable}"

  [[ "${HOME:-}" == "$RUNTIME_ROOT/home" ]] ||
    die "unexpected HOME: ${HOME:-<unset>}"
  [[ "${NPM_CONFIG_USERCONFIG:-}" == /dev/null ]] ||
    die 'NPM_CONFIG_USERCONFIG must be /dev/null'
  [[ "${NPM_CONFIG_GLOBALCONFIG:-}" == "$RUNTIME_ROOT/global-npmrc" ]] ||
    die 'NPM_CONFIG_GLOBALCONFIG must use the private runtime directory'
  [[ "${NPM_CONFIG_REGISTRY:-}" == https://registry.npmjs.org/ ]] ||
    die 'the public npm registry must be selected explicitly'
  [[ "${NPM_CONFIG_OMIT_LOCKFILE_REGISTRY_RESOLVED:-}" == false ]] ||
    die 'lockfile registry provenance must not be omitted'
  [[ ! -e /var/run/docker.sock ]] || die 'Docker socket must not enter the container'

  for key in \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
    http_proxy https_proxy all_proxy no_proxy \
    NPM_TOKEN NODE_AUTH_TOKEN SSH_AUTH_SOCK
  do
    [[ -z "${!key:-}" ]] || die "$key must not enter the container"
  done

  case "$mode" in
    generate)
      [[ -n "${PACKAGE_LOCK_NETWORK_MODE:-}" &&
         "${PACKAGE_LOCK_NETWORK_MODE:-}" != none ]] ||
        die 'generate mode requires the dedicated registry network'
      ;;
    validate)
      [[ "${PACKAGE_LOCK_NETWORK_MODE:-}" == none ]] ||
        die 'validate mode requires --network none'
      ;;
    *)
      die "unknown mode: $mode"
      ;;
  esac

  mkdir -p \
    "$RUNTIME_ROOT/home" \
    "$RUNTIME_ROOT/npm-cache" \
    "$RUNTIME_ROOT/xdg-cache" \
    "$RUNTIME_ROOT/xdg-config" \
    "$WORK_ROOT"
  : >"$RUNTIME_ROOT/global-npmrc"
  chmod 0600 "$RUNTIME_ROOT/global-npmrc"
}

print_runtime_identity() {
  local node_version
  local npm_version

  node_version="$(node --version)"
  npm_version="$(npm --version)"
  [[ "$node_version" == "$EXPECTED_NODE_VERSION" ]] ||
    die "unexpected Node version: $node_version"
  [[ "$npm_version" == "$EXPECTED_NPM_VERSION" ]] ||
    die "unexpected npm version: $npm_version"

  log "uid=$(id -u) gid=$(id -g)"
  log "node=$node_version npm=$npm_version"
  log "network_mode=${PACKAGE_LOCK_NETWORK_MODE:-unknown}"
}

validate_manifest_and_lock() {
  node --input-type=module - "$PACKAGE_PATH" "$LOCK_PATH" <<'NODE'
import fs from 'node:fs';

const [packagePath, lockPath] = process.argv.slice(2);
const errors = [];
let manifest;
let lock;

try {
  manifest = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
} catch (error) {
  console.error(`package.json is not valid JSON: ${error.message}`);
  process.exit(1);
}
try {
  lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
} catch (error) {
  console.error(`package-lock.json is not valid JSON: ${error.message}`);
  process.exit(1);
}

function normalized(value) {
  if (Array.isArray(value)) return value.map(normalized);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, normalized(value[key])]),
    );
  }
  return value;
}

function equal(left, right) {
  return JSON.stringify(normalized(left)) === JSON.stringify(normalized(right));
}

function normalizedBins(value) {
  return Object.fromEntries(
    Object.entries(value ?? {}).map(([name, target]) => [
      name,
      String(target).replace(/^\.\//, ''),
    ]),
  );
}

if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
  errors.push('package.json root must be an object');
}
if (typeof manifest?.name !== 'string' || !manifest.name ||
    typeof manifest?.version !== 'string' || !manifest.version) {
  errors.push('package.json must contain non-empty name and version fields');
}
if (lock?.lockfileVersion !== 3) {
  errors.push(`expected lockfileVersion 3, received ${lock?.lockfileVersion ?? '<missing>'}`);
}
if (lock?.requires !== true) {
  errors.push('package-lock.json must set requires=true');
}
if (lock?.name !== manifest?.name || lock?.version !== manifest?.version) {
  errors.push('package-lock root identity does not match package.json');
}

const root = lock?.packages?.[''];
if (!root || typeof root !== 'object') {
  errors.push('package-lock.json is missing packages[""]');
} else {
  if (root.name !== manifest.name || root.version !== manifest.version) {
    errors.push('packages[""] identity does not match package.json');
  }
  if ((root.license ?? null) !== (manifest.license ?? null)) {
    errors.push('packages[""] license does not match package.json');
  }
  for (const field of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    if (!equal(root[field] ?? {}, manifest[field] ?? {})) {
      errors.push(`packages[""] ${field} does not match package.json`);
    }
  }
  if (!equal(normalizedBins(root.bin), normalizedBins(manifest.bin))) {
    errors.push('packages[""] bin metadata does not match package.json');
  }
}

const packageEntries = Object.entries(lock?.packages ?? {});
if (packageEntries.length < 2) {
  errors.push('package-lock.json contains no resolved dependency packages');
}
for (const [packagePath, entry] of packageEntries) {
  if (!packagePath) continue;
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    errors.push(`${packagePath}: package record is not an object`);
    continue;
  }
  if (entry.link === true) {
    errors.push(`${packagePath}: link records are not allowed in the release lockfile`);
    continue;
  }
  if (typeof entry.resolved !== 'string') {
    errors.push(`${packagePath}: missing resolved URL`);
  } else {
    try {
      const resolved = new URL(entry.resolved);
      if (resolved.protocol !== 'https:' ||
          resolved.hostname !== 'registry.npmjs.org' ||
          resolved.port || resolved.username || resolved.password) {
        errors.push(`${packagePath}: unapproved resolved URL ${entry.resolved}`);
      }
    } catch {
      errors.push(`${packagePath}: invalid resolved URL ${entry.resolved}`);
    }
  }
  if (typeof entry.integrity !== 'string' ||
      !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(entry.integrity)) {
    errors.push(`${packagePath}: missing or invalid sha512 integrity`);
  }
}

if (errors.length) {
  for (const error of errors.slice(0, 50)) console.error(`lockfile: ${error}`);
  if (errors.length > 50) {
    console.error(`lockfile: ${errors.length - 50} more errors`);
  }
  process.exit(1);
}

console.error(`lockfile validated: ${packageEntries.length - 1} dependency records`);
NODE
}

check_advisories() {
  local npm_status

  if npm audit --omit=dev --json >"$AUDIT_PATH"; then
    npm_status=0
  else
    npm_status=$?
  fi

  node --input-type=module - "$AUDIT_PATH" "$npm_status" <<'NODE'
import fs from 'node:fs';

const [auditPath, rawStatus] = process.argv.slice(2);
const npmStatus = Number(rawStatus);
let report;
try {
  report = JSON.parse(fs.readFileSync(auditPath, 'utf8'));
} catch (error) {
  console.error(`invalid npm audit response: ${error.message}`);
  process.exit(1);
}

const counts = report.metadata?.vulnerabilities;
if (!counts || typeof counts.total !== 'number') {
  const message = report.error?.summary ?? report.error?.detail ?? 'missing totals';
  console.error(`npm audit did not return vulnerability totals: ${message}`);
  process.exit(1);
}

console.error(JSON.stringify({ npmStatus, vulnerabilities: counts }, null, 2));
if (npmStatus !== 0 || counts.total !== 0) {
  for (const [name, item] of Object.entries(report.vulnerabilities ?? {})) {
    console.error(`advisory: ${name} severity=${item.severity ?? 'unknown'}`);
  }
  process.exit(1);
}
NODE
}

run_generate() {
  local manifest_hash
  local lock_hash
  local entries=()

  shopt -s dotglob nullglob
  entries=("$WORK_ROOT"/*)
  if (( ${#entries[@]} != 0 )); then
    die 'generation workspace was not empty'
  fi

  cd "$WORK_ROOT" || die 'could not enter the generation workspace'

  command cat >"$PACKAGE_PATH"
  [[ -s "$PACKAGE_PATH" ]] || die 'package.json input was empty'
  manifest_hash="$(sha256sum "$PACKAGE_PATH")"

  node --input-type=module - "$PACKAGE_PATH" <<'NODE'
import fs from 'node:fs';
const path = process.argv[2];
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
if (!value || typeof value !== 'object' || Array.isArray(value)) process.exit(1);
NODE

  [[ ! -e "$LOCK_PATH" ]] || die 'generation workspace unexpectedly contains a lockfile'
  [[ ! -e "$WORK_ROOT/node_modules" ]] ||
    die 'generation workspace unexpectedly contains node_modules'

  log 'generating a fresh package-lock.json from package.json only'
  npm install \
    --package-lock-only \
    --package-lock=true \
    --lockfile-version=3 \
    --ignore-scripts \
    --legacy-peer-deps \
    --include=optional \
    --allow-directory=none \
    --allow-file=none \
    --allow-git=none \
    --allow-remote=none \
    --omit-lockfile-registry-resolved=false \
    --registry=https://registry.npmjs.org/ \
    --audit=false \
    --fund=false \
    --update-notifier=false >&2

  [[ -f "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] ||
    die 'npm did not produce a regular package-lock.json'
  [[ ! -e "$WORK_ROOT/node_modules" ]] ||
    die 'package-lock-only generation unexpectedly created node_modules'
  [[ "$(sha256sum "$PACKAGE_PATH")" == "$manifest_hash" ]] ||
    die 'npm changed the package.json input'

  validate_manifest_and_lock
  lock_hash="$(sha256sum "$LOCK_PATH")"
  log 'checking the generated production graph against the advisory service'
  check_advisories
  [[ "$(sha256sum "$PACKAGE_PATH")" == "$manifest_hash" &&
     "$(sha256sum "$LOCK_PATH")" == "$lock_hash" ]] ||
    die 'manifest or lockfile changed during the advisory check'
  log 'generated lockfile passed provenance, integrity, and advisory checks'

  command cat "$LOCK_PATH"
}

run_validate() {
  # Redirection order is intentional: preserve the Docker input stream on fd 3
  # before the heredoc replaces fd 0 with the JavaScript source for `node -`.
  node --input-type=module - "$PACKAGE_PATH" "$LOCK_PATH" 3<&0 <<'NODE'
import fs from 'node:fs';

const [packagePath, lockPath] = process.argv.slice(2);
const framed = fs.readFileSync(3);
const newline = framed.indexOf(0x0a);
if (newline < 1 || newline > 20) {
  console.error('invalid validation frame header');
  process.exit(1);
}
const header = framed.subarray(0, newline).toString('ascii');
if (!/^[1-9][0-9]*$/.test(header)) {
  console.error('invalid package.json byte count');
  process.exit(1);
}
const packageLength = Number(header);
const packageStart = newline + 1;
const lockStart = packageStart + packageLength;
if (!Number.isSafeInteger(packageLength) || packageLength > 1024 * 1024 ||
    lockStart >= framed.length || framed.length - lockStart > 64 * 1024 * 1024) {
  console.error('validation frame length is out of bounds');
  process.exit(1);
}
fs.writeFileSync(packagePath, framed.subarray(packageStart, lockStart), { mode: 0o600 });
fs.writeFileSync(lockPath, framed.subarray(lockStart), { mode: 0o600 });
NODE

  validate_manifest_and_lock
  log 'offline candidate validation passed'
}

usage() {
  cat <<'EOF'
Usage: regenerate-package-lock-container <generate|validate>

Internal helper. It refuses to run outside the capability-free, non-root
package-lock container. Generate mode accepts package.json on stdin and emits
only a fully validated package-lock.json on stdout. Validate mode accepts a
length-framed package.json and candidate lockfile on stdin and uses no network.
EOF
}

main() {
  local mode="${1:-}"

  case "$mode" in
    -h|--help)
      usage
      return 0
      ;;
    generate|validate)
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac

  assert_container_boundary "$mode"
  print_runtime_identity

  case "$mode" in
    generate) run_generate ;;
    validate) run_validate ;;
  esac
}

main "$@"
