#!/usr/bin/env bash
# Guest-only lifecycle driver. Host package managers and host Node are never used.
set -Eeuo pipefail
umask 077

[[ $# == 3 ]] || { echo 'usage: guest.sh install|smoke|full|verify|cleanup REPO RESULT_DIR' >&2; exit 2; }
ACTION=$1
REPO=$(realpath -e -- "$2")
RESULTS=$3
HARNESS=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $(id -un) == noshqemu && $HOME == /home/noshqemu ]] || { echo 'guest.sh requires the disposable noshqemu account' >&2; exit 2; }
[[ $REPO == /home/noshqemu/candidate || $REPO == /home/noshqemu/baseline ]] || exit 2
# The full suite can also exercise a committed baseline from before relocation.
LAUNCHER_DIR="$REPO/scripts"
[[ -f "$LAUNCHER_DIR/nosh.sh" ]] || LAUNCHER_DIR="$REPO"
[[ $RESULTS == /home/noshqemu/results && ! -L $RESULTS ]] || exit 2
case "$ACTION" in install|smoke|full|verify|cleanup) ;; *) exit 2 ;; esac
REV=$(git -C "$REPO" rev-parse HEAD)
STATE="$HOME/.cache/nosh-qemu/$REV"
OUT="$RESULTS/$REV"
IMAGE="nosh-qemu:${REV:0:12}"
GUARD=/usr/local/bin/nosh-guard
WORK="$STATE/workspace"
APPROVED=198.18.0.1
REJECTED=198.18.0.2
FIXTURE_PORT=18080
FIXTURE_PID=''
LEARN_PID=''
SMOKE_ID=''
INTERFACE_OWNED=false
RUN_IDS=()
mkdir -p -- "$STATE" "$OUT" "$WORK"
exec > >(tee -a "$OUT/$ACTION.log") 2>&1

record() {
  if command -v jq >/dev/null; then
    jq -nc --arg test "$1" --arg status "$2" --arg detail "${3:-}" \
      '{test:$test,status:$status,detail:$detail}' >>"$OUT/checks.ndjson"
  else
    printf 'check %s: %s (%s)\n' "$1" "$2" "${3:-}" >&2
  fi
}
blocked() { record "$ACTION" blocked "$*"; printf 'BLOCKED: %s\n' "$*" >&2; exit 2; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }
guard() { sudo -n -- "$GUARD" "$@"; }
run_action() {
  guard run --mode egress-learn --image "$IMAGE" --workdir "$WORK" --action "$1" --name "$2"
}

finish() {
  local result=$?
  trap - EXIT INT TERM
  if [[ -n $LEARN_PID ]]; then kill -TERM "$LEARN_PID" 2>/dev/null || true; wait "$LEARN_PID" || true; fi
  for run in "${RUN_IDS[@]}"; do
    run_action stop "$run" >/dev/null 2>&1 || true
    run_action rm "$run" >/dev/null 2>&1 || result=1
  done
  if [[ -z $SMOKE_ID && -f $STATE/smoke.cid ]]; then SMOKE_ID=$(cat "$STATE/smoke.cid"); fi
  if [[ $SMOKE_ID =~ ^[a-f0-9]{64}$ ]]; then
    # pipefail can leave smoke_guest before its normal log export. Preserve
    # diagnostics before removing the owned container, without masking failure.
    docker logs "$SMOKE_ID" >"$OUT/server.log" 2>&1 || true
    if ! docker rm -f "$SMOKE_ID" >/dev/null 2>&1; then
      if (( result == 0 )); then result=1; fi
    fi
    rm -f -- "$STATE/smoke.cid"
  fi
  if [[ -n $FIXTURE_PID ]]; then kill "$FIXTURE_PID" 2>/dev/null || true; wait "$FIXTURE_PID" 2>/dev/null || true; fi
  if [[ $INTERFACE_OWNED == true ]]; then sudo -n ip link delete nqemu-fixture || result=1; fi
  # Private signing material is never an evidence artifact.
  if [[ -d $STATE/roles ]]; then rm -rf -- "$STATE/roles"; fi
  sudo -n journalctl --unit nosh-guardd.service --no-pager --output short-iso \
    >"$OUT/guard-journal-$ACTION.log" 2>&1 || true
  if (( result == 0 )); then record "$ACTION" passed;
  elif (( result != 2 )); then record "$ACTION" failed "exit $result"; fi
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

prerequisites() {
  for command in docker jq python3 curl sudo tar timeout ip systemctl sha256sum; do
    command -v "$command" >/dev/null || blocked "missing guest command: $command"
  done
  [[ $(uname -m) == x86_64 ]] || blocked 'v1 requires an x86-64 guest'
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] || blocked 'cgroup v2 is unavailable'
  [[ -r /sys/kernel/btf/vmlinux ]] || blocked 'guest kernel BTF is unavailable'
  [[ -d /run/systemd/system ]] || blocked 'systemd is unavailable'
  sudo -n true || blocked 'passwordless guest sudo is unavailable'
  docker info >/dev/null 2>&1 || blocked 'guest Docker daemon is unavailable'
  docker buildx version >/dev/null 2>&1 || blocked 'guest Docker Buildx is unavailable'
  python3 - "$OUT/prerequisites.json" <<'PY'
import hashlib, json, pathlib, platform, subprocess, sys
def output(*args):
    return subprocess.check_output(args, text=True).strip()
btf = hashlib.sha256(pathlib.Path('/sys/kernel/btf/vmlinux').read_bytes()).hexdigest()
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'kernel': platform.release(), 'architecture': platform.machine(),
    'btfSha256': btf, 'cgroupControllers': pathlib.Path('/sys/fs/cgroup/cgroup.controllers').read_text().split(),
    'docker': json.loads(output('docker', 'version', '--format', '{{json .}}')),
    'buildx': output('docker', 'buildx', 'version'),
    'ipv6Forwarding': pathlib.Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip(),
    'ipv6Disabled': pathlib.Path('/proc/sys/net/ipv6/conf/all/disable_ipv6').read_text().strip(),
    'ipv6DefaultRoutes': output('ip', '-6', 'route', 'show', 'default'),
}, indent=2) + '\n')
PY
}

image_identity() {
  IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE")
  [[ $IMAGE_ID =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'invalid Nosh image identity'
}

tooling() {
  # Only explicitly supplied inputs and one optional signing role are mounted.
  docker run --rm --pull never --network none \
    --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 64 --memory 1g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=67108864 \
    --env HOME=/tmp/nosh-qemu \
    --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
    --mount "type=bind,src=$STATE/policy,dst=/policy-io" \
    "${ROLE_MOUNT[@]}" --entrypoint /usr/local/bin/node "$IMAGE_ID" "$@"
}
ROLE_MOUNT=()

installer() {
  local bundle
  bundle=$(cat "$STATE/installer-path")
  [[ $bundle == "$STATE"/bundle/*/install.sh && -f $bundle ]] || fail 'missing extracted installer'
  sudo -n bash "$bundle" "$@"
}

expected_manifest() {
  local installer_path
  installer_path=$(cat "$STATE/installer-path")
  [[ $installer_path == "$STATE"/bundle/*/install.sh ]] || fail 'unexpected installer path'
  sha256sum -- "${installer_path%/install.sh}/manifest.sha256" | awk '{print $1}'
}

assert_installed_identity() {
  local expected installed
  expected=$(expected_manifest)
  installed=$(sed -n 's/^MANIFEST_SHA256=//p' /etc/nosh-guard-install-layout.conf)
  [[ $expected =~ ^[a-f0-9]{64}$ && $installed == "$expected" ]] \
    || fail 'installed receipt does not match the selected commit bundle'
}

install_guest() {
  prerequisites
  local previous_manifest='' preservation=''
  if [[ -f /etc/nosh-guard-install-layout.conf ]]; then
    previous_manifest=$(sed -n 's/^MANIFEST_SHA256=//p' /etc/nosh-guard-install-layout.conf)
    [[ $previous_manifest =~ ^[a-f0-9]{64}$ ]] || fail 'existing installation has an invalid receipt'
    preservation="qemu-upgrade:$previous_manifest:$REV"
    printf '%s\n' "$preservation" | sudo -n tee "/etc/nosh-guard/qemu-preservation-$REV" >/dev/null
    printf '%s\n' "$preservation" | sudo -n tee "/var/lib/nosh-guard/qemu-preservation-$REV" >/dev/null
    sudo -n chmod 0600 "/etc/nosh-guard/qemu-preservation-$REV" "/var/lib/nosh-guard/qemu-preservation-$REV"
  fi
  [[ ! -e $STATE/bundle ]] || fail 'install state already exists for this commit'
  mkdir -m 0700 "$STATE/archives" "$STATE/bundle"
  (cd "$REPO"; bash scripts/build-nosh-guard-host-bundle.sh --output-dir "$STATE/archives")
  local archives=("$STATE/archives/"*.tar.gz)
  [[ ${#archives[@]} == 1 && -f ${archives[0]} ]] || fail 'expected exactly one host bundle'
  (cd "$STATE/archives"; sha256sum -c -- "${archives[0]##*/}.sha256")
  sha256sum -- "${archives[0]}" >"$OUT/guard-bundle.sha256"
  tar -xzf "${archives[0]}" -C "$STATE/bundle"
  local installers=("$STATE/bundle/"*/install.sh)
  [[ ${#installers[@]} == 1 && -f ${installers[0]} ]] || fail 'host bundle installer missing'
  printf '%s\n' "${installers[0]}" >"$STATE/installer-path"
  # Both commits are explicit test inputs in this disposable guest. Replace
  # bundle-owned adapter/version files when the candidate upgrades the baseline.
  installer install --enable-now --deep-verify --replace-config
  assert_installed_identity
  if [[ -n $previous_manifest ]]; then
    [[ $(sudo -n cat "/etc/nosh-guard/qemu-preservation-$REV") == "$preservation" \
      && $(sudo -n cat "/var/lib/nosh-guard/qemu-preservation-$REV") == "$preservation" ]] \
      || fail 'upgrade changed preserved operator configuration or evidence state'
    jq -n --arg before "$previous_manifest" --arg after "$(expected_manifest)" \
      '{previousManifest:$before,candidateManifest:$after,operatorConfigPreserved:true,evidencePreserved:true}' \
      >"$OUT/upgrade.json"
    record upgrade-preservation passed 'operator configuration and evidence markers survived candidate installation'
  fi
  (cd "$REPO"; bash "$LAUNCHER_DIR/setup-nosh.sh" --require-guard --replace-links)
  (cd "$REPO"; TARGET=base IMAGE_NAME="$IMAGE" bash "$LAUNCHER_DIR/build-nosh.sh")
  image_identity
  jq -n --arg commit "$REV" --arg image "$IMAGE_ID" --arg manifest "$(expected_manifest)" \
    '{commit:$commit,image:$image,manifestSha256:$manifest}' >"$OUT/installed.json"
  record host-install passed 'checksummed bundle, deep verification, setup, base image'
}

verify_guest() {
  prerequisites
  installer verify --deep
  assert_installed_identity
  sudo -n systemctl is-active --quiet nosh-guardd.service
  (cd "$REPO"; bash "$LAUNCHER_DIR/setup-nosh.sh" --check --require-guard)
  if [[ -f $STATE/activated ]]; then
    guard ebpf status --workdir "$WORK" --json >"$OUT/activation-after-boot.json"
    local before after
    before=$(jq -er '.activeGrantSetDigest' "$OUT/activation-after.json")
    after=$(jq -er '.activeGrantSetDigest' "$OUT/activation-after-boot.json")
    [[ $before == "$after" ]] || fail 'reboot changed active grant-set identity'
  fi
}

smoke_guest() {
  verify_guest
  image_identity
  local name="nosh-qemu-${REV:0:12}-smoke"
  docker inspect "$name" >/dev/null 2>&1 && fail "smoke container already exists: $name"
  # The launcher intentionally attaches a TTY. Send exit after startup while
  # --persist leaves the service available to the isolated test client.
  python3 - "$LAUNCHER_DIR/nosh.sh" "$IMAGE_ID" "$WORK" "$name" "$STATE/smoke.cid" <<'PY'
import os, pty, select, signal, subprocess, sys, time
launcher, image, work, name, receipt = sys.argv[1:]
os.environ['NOTTY_BASIC_AUTH_USERNAME'] = 'qemu-smoke'
os.environ['NOTTY_BASIC_AUTH_PASSWORD'] = 'qemu-smoke'
pid, fd = pty.fork()
if pid == 0:
    os.execv('/bin/bash', ['bash', launcher, 'start', '--security-mode', 'legacy',
        '--image', image, '--workdir', work, '--name', name, '--persist', '--start-app',
        '--no-collab', '--no-oauth', '--no-otp', '--publish', '127.0.0.1:3000'])
deadline, sent, reaped = time.monotonic() + 180, False, False
def capture_owned_container():
    state = subprocess.run(['docker', 'inspect', '--format', '{{.Id}} {{.State.Running}}', name],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    fields = state.stdout.split()
    if state.returncode == 0 and len(fields) == 2:
        with open(receipt, 'w') as output: output.write(fields[0] + '\n')
        return fields[1] == 'true'
    return False
try:
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.25)
        if readable:
            try: data = os.read(fd, 65536)
            except OSError: break
            if not data: break
            sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        if capture_owned_container() and not sent:
            time.sleep(1)
            os.write(fd, b'exit\n'); sent = True
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            reaped = True
            sys.exit(os.waitstatus_to_exitcode(status))
    else:
        raise TimeoutError('Nosh launcher did not return')
    _, status = os.waitpid(pid, 0)
    reaped = True
    sys.exit(os.waitstatus_to_exitcode(status))
finally:
    capture_owned_container()
    if not reaped:
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
    os.close(fd)
PY
  SMOKE_ID=$(docker inspect --format '{{.Id}}' "$name")
  [[ $SMOKE_ID =~ ^[a-f0-9]{64}$ ]] || fail 'invalid smoke container ID'
  docker run --rm --pull never --network "container:$SMOKE_ID" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --tmpfs /tmp:rw,nosuid,nodev,noexec \
    --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
    --entrypoint /usr/local/bin/node "$IMAGE_ID" /harness/terminal-smoke.mjs \
    | tee "$OUT/terminal-smoke.ndjson"
  docker logs "$SMOKE_ID" >"$OUT/server.log" 2>&1
  docker rm -f "$SMOKE_ID" >/dev/null
  rm -f -- "$STATE/smoke.cid"
  SMOKE_ID=''
}

fixture_start() {
  [[ ! -e $STATE/fixture ]] || fail 'fixture state already exists'
  mkdir "$STATE/fixture"
  sudo -n ip link show nqemu-fixture >/dev/null 2>&1 && fail 'fixture interface already exists'
  sudo -n ip link add nqemu-fixture type dummy
  INTERFACE_OWNED=true
  sudo -n ip address add "$APPROVED/32" dev nqemu-fixture
  sudo -n ip address add "$REJECTED/32" dev nqemu-fixture
  sudo -n ip link set nqemu-fixture up
  python3 "$HARNESS/guest-fixture.py" "$STATE/fixture" &
  FIXTURE_PID=$!
  for ((attempt=0; attempt<100; attempt++)); do
    [[ ! -f $STATE/fixture/ready ]] || break
    kill -0 "$FIXTURE_PID" 2>/dev/null || fail 'fixture server exited'
    sleep 0.1
  done
  [[ -f $STATE/fixture/ready ]] || fail 'fixture server did not start'
  for address in "$APPROVED" "$REJECTED"; do
    [[ $(curl --noproxy '*' --fail --silent --max-time 5 "http://$address:$FIXTURE_PORT/") == "$address" ]] \
      || fail 'fixture endpoint is not reachable from guest'
  done
}

probe() {
  local container=$1 address=$2 expected=$3 before after status=0 body
  before=$(jq -er --arg address "$address" '.[$address]' "$STATE/fixture/counts.json")
  body=$(docker exec "$container" curl --noproxy '*' --silent --show-error --fail \
    --connect-timeout 3 --max-time 5 "http://$address:$FIXTURE_PORT/") || status=$?
  after=$(jq -er --arg address "$address" '.[$address]' "$STATE/fixture/counts.json")
  if [[ $expected == allow ]]; then
    [[ $status == 0 && $body == "$address" && $after -gt $before ]] || fail "expected successful $address request"
  else
    [[ $status != 0 && $after == "$before" ]] || fail "denied $address reached its fixture"
  fi
}

copy_evidence() {
  local manifest=$1 label=$2 mode=$3
  sudo -n cat "$manifest" >"$OUT/$label-manifest.json"
  local evidence
  evidence=$(jq -er '.sources[] | select(.name == "nosh-egress") | .path' "$OUT/$label-manifest.json")
  [[ $evidence == /var/lib/nosh-guard/* ]] || fail 'unexpected Guard evidence path'
  sudo -n cat "$evidence" >"$OUT/$label-egress.ndjson"
  docker run --rm --pull never --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
    --mount "type=bind,src=$OUT,dst=/evidence,readonly" \
    --entrypoint /usr/local/bin/node "$IMAGE_ID" /harness/guard-scenarios.mjs evidence \
    "/evidence/$label-manifest.json" "$mode" "$APPROVED" "$REJECTED" "/evidence/$label-egress.ndjson"
}

learn() {
  local label=$1 both=$2 name="nosh-qemu-${REV:0:12}-$1" container=''
  sudo -n -- "$GUARD" net learn --workdir "$WORK" --image "$IMAGE_ID" --name "$name" \
    --no-start-app --no-collab --duration 45 --json >"$OUT/$label.json" &
  LEARN_PID=$!
  for ((attempt=0; attempt<300; attempt++)); do
    container=$(docker inspect --format '{{if and .State.Running (not .State.Paused)}}{{.Id}}{{end}}' "$name" 2>/dev/null || true)
    [[ -z $container ]] || break
    kill -0 "$LEARN_PID" 2>/dev/null || fail 'learning process exited before runner release'
    sleep 0.2
  done
  [[ $container =~ ^[a-f0-9]{64}$ ]] || fail 'learning runner was not released'
  probe "$container" "$APPROVED" allow
  if [[ $both == true ]]; then probe "$container" "$REJECTED" allow; fi
  wait "$LEARN_PID"
  LEARN_PID=''
  jq -e '.observationComplete == true and (.revision | type == "string")' "$OUT/$label.json" >/dev/null
  if [[ $both == true ]]; then
    copy_evidence "$(jq -er '.evidenceManifest' "$OUT/$label.json")" "$label" learn
  fi
}

stop_run() {
  local id=$1 label=$2 mode=$3
  run_action stop "$id" >"$OUT/$label-stop.json"
  copy_evidence "$(jq -er '.evidenceManifest' "$OUT/$label-stop.json")" "$label" "$mode"
  run_action rm "$id" >"$OUT/$label-remove.json"
  RUN_IDS=()
}

audit_guest() {
  local profile id container
  profile=$(jq -er '.profileDirectory' "$OUT/learn-approved.json")
  guard run --action start --mode egress-audit --workdir "$WORK" --image "$IMAGE_ID" \
    --name "nosh-qemu-${REV:0:12}-audit" --profile-dir "$profile" --no-start-app --no-collab \
    >"$OUT/audit-start.json"
  id=$(jq -er '.runId' "$OUT/audit-start.json"); RUN_IDS+=("$id")
  container=$(jq -er '.containerId' "$OUT/audit-start.json")
  probe "$container" "$APPROVED" allow
  probe "$container" "$REJECTED" allow
  stop_run "$id" audit audit
}

activate_guest() {
  mkdir -m 0700 "$STATE/policy" "$STATE/roles" "$STATE/roles/review" "$STATE/roles/deployment"
  local policy="$STATE/policy" role candidate revision audience workspace_key
  candidate=$(jq -er '.reviewCandidateDirectory' "$OUT/learn-approved.json")
  revision=$(jq -er '.revision' "$OUT/learn-approved.json")
  workspace_key=$(basename -- "$(dirname -- "$candidate")")
  [[ $workspace_key =~ ^[a-f0-9]{64}$ && ${candidate##*/} == "$revision" ]] \
    || fail 'runtime candidate directory does not preserve workspace/revision identity'
  mkdir -m 0700 -p "$policy/candidates/$workspace_key"
  cp -a -- "$candidate" "$policy/candidates/$workspace_key/$revision"
  cp -- "$(jq -er '.reviewTargetContext' "$OUT/learn-approved.json")" "$policy/context.json"
  bash "$REPO/scripts/nosh-inventory.sh" --workdir "$REPO" --image "$IMAGE_ID" \
    --tooling "$IMAGE_ID" --output "$policy/inventory"
  tooling /app/scripts/nosh-guard.mjs review bundle \
    --runtime-candidate "/policy-io/candidates/$workspace_key/$revision" \
    --literal-endpoints --sbom-source /policy-io/inventory/source.spdx.json \
    --sbom-image /policy-io/inventory/image.spdx.json --output /policy-io/review
  tooling /harness/guard-scenarios.mjs decisions /policy-io/review /policy-io/decisions.json "$APPROVED" "$FIXTURE_PORT"
  tooling /app/scripts/nosh-guard.mjs policy project --bundle /policy-io/review \
    --decisions /policy-io/decisions.json --target guard-ebpf --context /policy-io/context.json \
    --output /policy-io/projected >"$policy/projection.json"
  tooling /harness/guard-scenarios.mjs projection /policy-io/projection.json
  for role in review deployment; do
    docker run --rm --pull never --network none --user "$(id -u):$(id -g)" \
      --read-only --cap-drop ALL --security-opt no-new-privileges:true \
      --tmpfs /tmp:rw,nosuid,nodev,noexec \
      --mount "type=bind,src=$STATE/roles/$role,dst=/role" \
      --entrypoint /usr/local/bin/node "$IMAGE_ID" \
      /app/scripts/nosh-guard.mjs review keygen --output /role/key
  done
  audience="qemu-$(cat /proc/sys/kernel/random/uuid)"
  sudo -n install -d -o root -g root -m 0700 /etc/nosh-guard/ebpf-trust
  for role in review deployment; do
    sudo -n install -o root -g root -m 0600 "$STATE/roles/$role/key/public.pem" \
      "/etc/nosh-guard/ebpf-trust/$role-public.pem"
  done
  jq -n --arg audience "$audience" '{schemaVersion:1,kind:"NoshGuardEbpfDeploymentTrust",
    backendAbi:"nosh-egress-v2",reviewPublicKey:"/etc/nosh-guard/ebpf-trust/review-public.pem",
    deploymentPublicKey:"/etc/nosh-guard/ebpf-trust/deployment-public.pem",
    reviewAudience:"qemu-review",deploymentAudience:$audience}' >"$policy/trust.json"
  sudo -n install -o root -g root -m 0600 "$policy/trust.json" /etc/nosh-guard/ebpf-deployment-trust.json
  cp "$STATE/roles/review/key/public.pem" "$policy/review-public.pem"
  ROLE_MOUNT=(--mount "type=bind,src=$STATE/roles/review/key/private.pem,dst=/run/review.pem,readonly")
  tooling /app/scripts/nosh-guard.mjs review approve --bundle /policy-io/review \
    --decisions /policy-io/decisions.json --policy /policy-io/projected --reviewer qemu-test \
    --audience qemu-review --key /run/review.pem \
    --confirmation "$(jq -er '.targetReviewSetDigest' "$policy/projection.json")" --output /policy-io/approval
  guard ebpf status --workdir "$WORK" --json >"$OUT/activation-before.json"
  ROLE_MOUNT=(--mount "type=bind,src=$STATE/roles/deployment/key/private.pem,dst=/run/deployment.pem,readonly")
  tooling /app/scripts/nosh-guard.mjs deployment grant --policy /policy-io/projected \
    --approval /policy-io/approval/approval-envelope.dsse.json --review-key /policy-io/review-public.pem \
    --review-audience qemu-review --deployment-key /run/deployment.pem --audience "$audience" \
    --target-binding-digest "$(jq -er '.targetBindingDigest' "$policy/projection.json")" \
    --active-grant-set-digest "$(jq -er '.activeGrantSetDigest' "$OUT/activation-before.json")" \
    --ttl-seconds 3600 --output /policy-io/grant
  ROLE_MOUNT=()
  mkdir -m 0700 "$policy/activation"
  cp -a "$policy/projected" "$policy/activation/policy"
  cp "$policy/approval/approval-envelope.dsse.json" "$policy/activation/"
  cp "$policy/grant/deployment-grant.dsse.json" "$policy/activation/"
  guard ebpf activate --workdir "$WORK" --learn-revision "$revision" \
    --bundle "$policy/activation" --target-context "$policy/context.json" >"$OUT/activation.json"
  guard ebpf status --workdir "$WORK" --json >"$OUT/activation-after.json"
  touch "$STATE/activated"
  cp "$policy/projection.json" "$OUT/projection.json"
  record signed-activation passed 'independent ephemeral review/deployment roles'
}

enforce_guest() {
  local label=$1 id container
  guard net enforce --workdir "$WORK" >"$OUT/$label-start.json"
  id=$(jq -er '.runId' "$OUT/$label-start.json"); RUN_IDS+=("$id")
  container=$(jq -er '.containerId' "$OUT/$label-start.json")
  probe "$container" "$APPROVED" allow
  probe "$container" "$REJECTED" deny
  stop_run "$id" "$label" enforce
}

full_guest() {
  prerequisites
  [[ $(cat /proc/sys/net/ipv6/conf/all/forwarding) == 1 \
    && $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) == 0 \
    && -n $(ip -6 route show default) ]] || blocked 'scoped egress requires IPv6 forwarding and a default route'
  image_identity
  sudo -n bash "$REPO/scripts/nosh-guard-doctor.sh" --mode egress-learn --runner-image "$IMAGE_ID" \
    --deep >"$OUT/scoped-doctor.log" 2>&1 || blocked 'scoped eBPF prerequisites failed; see scoped-doctor.log'
  # This wrapper preserves the existing development-versus-release distinction.
  (cd "$REPO"; bash scripts/ci-release-audit.sh)
  cp -a "$REPO/.release-audit" "$OUT/release-audit"
  mkdir "$STATE/build-context"
  local profile_base
  profile_base=$(sed -n 's/^ARG NODE_IMAGE=//p' "$REPO/Dockerfile.nosh")
  [[ $profile_base =~ ^node:[a-zA-Z0-9._-]+@sha256:[a-f0-9]{64}$ ]] || fail 'missing pinned public profiling base'
  printf 'FROM %s\nRUN printf qemu-build-profile >/tmp/qemu-profile-marker\n' "$profile_base" >"$STATE/build-context/Dockerfile"
  (cd "$REPO"; bash "$LAUNCHER_DIR/nosh.sh" build profile --cache-mode cold --private-json \
    --tag "nosh-qemu-profile:${REV:0:12}" "$STATE/build-context") >"$OUT/build-profile.json"
  record build-profile passed
  fixture_start
  learn learn-both true
  learn learn-approved false
  audit_guest
  activate_guest
  enforce_guest enforce
  sudo -n systemctl restart nosh-guardd.service
  sudo -n systemctl is-active --quiet nosh-guardd.service
  enforce_guest enforce-after-restart
  jq -n --arg workdir "$WORK" --arg image "$IMAGE_ID" \
    '{mode:"enforce",action:"start",workdir:$workdir,image:$image,name:"qemu-standalone-rejection"}' >"$STATE/standalone-request.json"
  sudo -n curl --silent --show-error --max-time 30 --unix-socket /run/nosh-guardd.sock \
    --header 'Content-Type: application/json' --data-binary "@$STATE/standalone-request.json" \
    http://localhost/v1/runs >"$OUT/standalone-rejection.json"
  jq -e '.error.code == "GUARD_STANDALONE_INGRESS_UNAVAILABLE"' "$OUT/standalone-rejection.json" >/dev/null
  cp "$STATE/fixture/counts.json" "$OUT/fixture-counts.json"
  record standalone-enforcement-rejected passed GUARD_STANDALONE_INGRESS_UNAVAILABLE
}

cleanup_guest() {
  local sentinel="/var/lib/nosh-guard/qemu-preservation-$REV"
  # The installer keeps /etc/nosh-guard root-owned with mode 0750.
  sudo -n test -f /etc/nosh-guard/adapters.json || fail 'cleanup requires installed configuration'
  sudo -n install -d -m 0700 /var/lib/nosh-guard
  printf '%s\n' "$REV" | sudo -n tee "$sentinel" >/dev/null
  installer uninstall
  [[ $(sudo -n cat "$sentinel") == "$REV" ]] || fail 'uninstall removed preserved evidence'
  [[ ! -e /usr/local/bin/nosh-guard ]] || fail 'uninstall left Guard launcher'
  sudo -n test -f /etc/nosh-guard/adapters.json || fail 'uninstall removed preserved configuration'
  [[ ! -S /run/nosh-guardd.sock ]] || fail 'uninstall left the Guard management socket'
  if sudo -n systemctl is-active --quiet nosh-guardd.service; then fail 'uninstall left the daemon running'; fi
  [[ -z $(docker ps -aq --filter label=io.notty.guard.managed=true) ]] || fail 'Guard containers remain after teardown'
  [[ -z $(docker network ls -q --filter label=io.notty.guard.managed=true) ]] || fail 'Guard networks remain after teardown'
  sudo -n python3 - <<'PY'
import pathlib
root = pathlib.Path('/sys/fs/bpf/nosh-guard')
if root.exists() and any(root.iterdir()):
    raise SystemExit('Guard pinned BPF state remains after teardown')
PY
  record uninstall-preserves-state passed
  # A normal uninstall removes the install receipt. Reinstall the same verified
  # bundle before exercising the explicit purge contract without --force.
  installer install --enable-now --deep-verify
  installer uninstall --purge-config --purge-state
  sudo -n test ! -e /var/lib/nosh-guard || fail 'explicit purge left Guard state'
  sudo -n test ! -e /etc/nosh-guard/adapters.json || fail 'explicit purge left installed configuration'
  [[ ! -S /run/nosh-guardd.sock ]] || fail 'explicit purge left the Guard management socket'
  record explicit-purge passed
}

case "$ACTION" in
  install) install_guest ;;
  verify) verify_guest ;;
  smoke) smoke_guest ;;
  full) full_guest ;;
  cleanup) cleanup_guest ;;
esac
