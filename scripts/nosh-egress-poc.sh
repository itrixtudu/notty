#!/usr/bin/env bash
# Disposable, offline live-cgroup proof. --baseline needs Docker; BPF modes need root.
set -euo pipefail
umask 077

POC_SCRIPT=$(readlink -f -- "${BASH_SOURCE[0]}")
POC_REPO=$(dirname -- "$(dirname -- "$POC_SCRIPT")")
POC_MODE=${1:---help}
POC_HOLD_PHASE=''
POC_CLIENT_IMAGE=sha256:5e7abcdd20216bbeedf1369529564ffd60f830ed3540c477938ca580b645dff5
POC_SERVER_IMAGE=sha256:9da6b4e352d0d5c94963eba1832408f5b7b08839cd8be9b6610c05de5118c704
POC_TOOL_IMAGE=sha256:a78b7bd9ef8d6f168aba70f4f83942bc4382b49d7a1f1bd5783135d73de27aec
POC_LOADER=/opt/notty/libexec/nosh-guard/nosh-egress-loader
POC_OBJECT=sha256:2dd222da3474b8d091e00215bf788d9cf626c027f5286354a3bd3aaf2fc7dd30

poc_die() { printf 'nosh-egress-poc: %s\n' "$*" >&2; exit 1; }

case "$POC_MODE" in
  --help)
    cat <<'HELP'
Usage: bash scripts/nosh-egress-poc.sh --baseline | --run | --hold allowA|allowB

--baseline  Check both local HTTP endpoints with the cached curl image, then
            remove the test containers/network. Does not load or attach BPF.
--run       ROOT ONLY: run baseline, allow-A, allow-B, and verified cleanup in
            a private mount namespace using the installed eBPF loader.
--hold      ROOT ONLY: verify one policy and keep its client running. Enter
            it using the printed docker exec command in another host terminal.
            Ctrl-C here stops the holder and cleans up its resources.

No image pulls, package installs, external HTTP requests, published ports,
Guard daemon calls, trust-store changes, or Docker sockets inside containers.
Root execution requires explicit operator approval. Nothing invokes sudo.
HELP
    exit 0 ;;
  --baseline) [[ $# == 1 ]] || poc_die 'unexpected arguments' ;;
  --run)
    [[ $# == 1 && $EUID == 0 ]] || poc_die '--run requires root on the host'
    exec unshare --mount --propagation private -- /bin/bash "$POC_SCRIPT" \
      --private "$(readlink /proc/self/ns/mnt)" ;;
  --hold)
    [[ $# == 2 && ( $2 == allowA || $2 == allowB ) ]] || poc_die '--hold requires allowA or allowB'
    [[ $EUID == 0 ]] || poc_die '--hold requires root on the host'
    exec unshare --mount --propagation private -- /bin/bash "$POC_SCRIPT" \
      --private "$(readlink /proc/self/ns/mnt)" "$2" ;;
  --private)
    [[ ( $# == 2 || $# == 3 ) && $EUID == 0 ]] || poc_die 'invalid private-namespace invocation'
    POC_HOLD_PHASE=${3:-}
    [[ -z $POC_HOLD_PHASE || $POC_HOLD_PHASE == allowA || $POC_HOLD_PHASE == allowB ]] || poc_die 'invalid held policy'
    [[ $(readlink /proc/self/ns/mnt) != "$2" ]] || poc_die 'mount namespace was not isolated'
    mount --make-rprivate /
    [[ $(findmnt -n -o PROPAGATION /) == private ]] || poc_die 'mount propagation is not private'
    ;;
  *) poc_die 'use --help, --baseline, --run, or --hold allowA|allowB' ;;
esac

for POC_COMMAND in docker jq timeout stat sha256sum readlink; do
  command -v "$POC_COMMAND" >/dev/null || poc_die "missing command: $POC_COMMAND"
done
[[ -S /var/run/docker.sock ]] || poc_die 'local Docker socket is missing'
POC_EXPORT_BASE="$POC_REPO/cache/policy-cli-test/enforce-poc"
if [[ $POC_MODE == --private ]]; then
  POC_STAGE=$(mktemp -d /root/nosh-egress-poc.XXXXXX)
else
  mkdir -p -- "$POC_EXPORT_BASE"
  POC_STAGE=$(mktemp -d "$POC_EXPORT_BASE/baseline.XXXXXX")
fi
POC_SESSION="nosh-egress-poc-$(cat /proc/sys/kernel/random/uuid)"
POC_NETWORK_ID=''
POC_CLIENT=''
POC_SERVER_A=''
POC_SERVER_B=''
POC_COLLECTOR=''
POC_COLLECTOR_START=''
POC_CGROUP_ID=''
POC_CGROUP_PATH=''
POC_CLIENT_PID=''
POC_CLIENT_START=''
POC_PIN_ROOT=''
POC_BPFFS=false
POC_CLEANED=false
POC_SUCCESS=''
POC_HOLD_STARTED=false
POC_HOLD_STOP=false
POC_HOLD_STOP_REASON=''
POC_ALLOWED_URL=''
POC_DENIED_URL=''
POC_CONTAINERS=()
mkdir -m 700 -- "$POC_STAGE/docker-config"

poc_docker() {
  timeout --kill-after=5s 45s docker --host unix:///var/run/docker.sock \
    --config "$POC_STAGE/docker-config" "$@"
}

poc_start_time() {
  local process_stat process_fields
  local -a process_parts
  [[ $1 =~ ^[1-9][0-9]*$ && -r /proc/$1/stat ]] || return 1
  process_stat=$(<"/proc/$1/stat") || return 1
  process_fields=${process_stat##*) }
  read -r -a process_parts <<< "$process_fields"
  [[ ${process_parts[19]:-} =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${process_parts[19]}"
}

poc_stop_collector() {
  local result=0 attempt current
  [[ -n $POC_COLLECTOR ]] || return 0
  current=$(poc_start_time "$POC_COLLECTOR") || current=''
  if [[ -n $current && $current == "$POC_COLLECTOR_START" ]]; then
    kill -TERM "$POC_COLLECTOR" || result=1
    for ((attempt=0; attempt<50; attempt++)); do
      current=$(poc_start_time "$POC_COLLECTOR") || current=''
      [[ $current == "$POC_COLLECTOR_START" ]] || break
      sleep 0.1
    done
    if [[ $current == "$POC_COLLECTOR_START" ]]; then
      kill -KILL "$POC_COLLECTOR" || true
      result=1
    fi
  fi
  wait "$POC_COLLECTOR" || result=1
  POC_COLLECTOR=''
  POC_COLLECTOR_START=''
  return "$result"
}

poc_cleanup() {
  local ok=true containers_removed=true network_removed=true pins_removed=true
  local container network remaining discovered
  local -a containers=() networks=()
  local -A known=()
  [[ $POC_CLEANED == false ]] || return 0
  POC_CLEANED=true
  if [[ -n $POC_CLIENT ]]; then
    poc_docker pause "$POC_CLIENT" > /dev/null 2>> "$POC_STAGE/cleanup.log" || true
  fi
  poc_stop_collector || ok=false
  if [[ -n $POC_PIN_ROOT && -e $POC_PIN_ROOT ]]; then
    "$POC_LOADER" snapshot --pin-root "$POC_PIN_ROOT" \
      > "$POC_STAGE/cleanup-snapshot.jsonl" 2>> "$POC_STAGE/cleanup.log" || true
    if ! "$POC_LOADER" detach --pin-root "$POC_PIN_ROOT" \
        > "$POC_STAGE/cleanup-detach.json" 2>> "$POC_STAGE/cleanup.log"; then
      ok=false
    fi
    [[ ! -e $POC_PIN_ROOT ]] || pins_removed=false
  fi
  for container in "$POC_SERVER_A" "$POC_SERVER_B"; do
    [[ -n $container ]] || continue
    if [[ $container == "$POC_SERVER_A" ]]; then
      poc_docker logs "$container" > "$POC_STAGE/server-a.jsonl" 2>> "$POC_STAGE/cleanup.log" || ok=false
    else
      poc_docker logs "$container" > "$POC_STAGE/server-b.jsonl" 2>> "$POC_STAGE/cleanup.log" || ok=false
    fi
  done
  # On failure, kill only this test's containers even if native detach failed.
  # Destroying the client cgroup closes the fail-open window; never leave it running.
  # A timed-out Docker create may have committed without returning its ID.
  # Recover only resources carrying this invocation's fresh UUID label.
  containers=("${POC_CONTAINERS[@]}")
  if discovered=$(poc_docker ps --all --no-trunc --filter "label=io.notty.egress-poc.session=$POC_SESSION" --format '{{.ID}}'); then
    while IFS= read -r container; do
      [[ -n $container ]] && containers+=("$container")
    done <<< "$discovered"
  else
    containers_removed=false
  fi
  for container in "${containers[@]}"; do
    [[ $container =~ ^[a-f0-9]{64}$ ]] || { containers_removed=false; continue; }
    [[ -z ${known[$container]:-} ]] || continue
    known[$container]=1
    if ! poc_docker inspect --type container "$container" | jq -e --arg session "$POC_SESSION" \
        'length == 1 and .[0].Config.Labels["io.notty.egress-poc.session"] == $session' >/dev/null; then
      containers_removed=false
      continue
    fi
    poc_docker rm --force "$container" > /dev/null 2>> "$POC_STAGE/cleanup.log" || containers_removed=false
  done
  if remaining=$(poc_docker ps --all --no-trunc --filter "label=io.notty.egress-poc.session=$POC_SESSION" --format '{{.ID}}'); then
    [[ -z $remaining ]] || containers_removed=false
  else
    containers_removed=false
  fi
  if discovered=$(poc_docker network ls --no-trunc --filter "label=io.notty.egress-poc.session=$POC_SESSION" --format '{{.ID}}'); then
    while IFS= read -r network; do
      [[ -n $network ]] && networks+=("$network")
    done <<< "$discovered"
  else
    network_removed=false
  fi
  [[ -z $POC_NETWORK_ID ]] || networks+=("$POC_NETWORK_ID")
  known=()
  for network in "${networks[@]}"; do
    [[ $network =~ ^[a-f0-9]{64}$ ]] || { network_removed=false; continue; }
    [[ -z ${known[$network]:-} ]] || continue
    known[$network]=1
    if poc_docker network inspect "$network" | jq -e --arg session "$POC_SESSION" \
        'length == 1 and .[0].Name == $session and .[0].Labels["io.notty.egress-poc.session"] == $session' >/dev/null; then
      poc_docker network rm "$network" > /dev/null 2>> "$POC_STAGE/cleanup.log" || network_removed=false
    else
      network_removed=false
    fi
  done
  if remaining=$(poc_docker network ls --no-trunc --filter "label=io.notty.egress-poc.session=$POC_SESSION" --format '{{.ID}}'); then
    [[ -z $remaining ]] || network_removed=false
  else
    network_removed=false
  fi
  if [[ $POC_BPFFS == true ]]; then
    if remaining=$(find /sys/fs/bpf/nosh-guard -mindepth 1 -print -quit); then
      [[ -z $remaining ]] || pins_removed=false
    else
      pins_removed=false
    fi
    umount /sys/fs/bpf || ok=false
    POC_BPFFS=false
  fi
  [[ $containers_removed == true && $network_removed == true && $pins_removed == true ]] || ok=false
  jq -n --argjson ok "$ok" --argjson containersRemoved "$containers_removed" \
    --argjson networkRemoved "$network_removed" --argjson pinRootsRemoved "$pins_removed" \
    '{ok:$ok,containersRemoved:$containersRemoved,networkRemoved:$networkRemoved,pinRootsRemoved:$pinRootsRemoved}' \
    > "$POC_STAGE/cleanup.json"
  [[ $ok == true ]]
}

poc_cleanup_tools() {
  local remaining tool_id result=0
  if remaining=$(poc_docker ps --all --no-trunc --filter "label=io.notty.egress-poc.session=$POC_SESSION" \
      --filter label=io.notty.egress-poc.role=tool --format '{{.ID}}'); then
    while IFS= read -r tool_id; do
      [[ -n $tool_id ]] || continue
      [[ $tool_id =~ ^[a-f0-9]{64}$ ]] || { result=1; continue; }
      poc_docker rm --force "$tool_id" >/dev/null || result=1
    done <<< "$remaining"
  else
    result=1
  fi
  if remaining=$(poc_docker ps --all --no-trunc --filter "label=io.notty.egress-poc.session=$POC_SESSION" \
      --filter label=io.notty.egress-poc.role=tool --format '{{.ID}}'); then
    [[ -z $remaining ]] || result=1
  else
    result=1
  fi
  return "$result"
}

poc_export() {
  local owner owner_name export_dir
  [[ $POC_MODE == --private ]] || return 0
  owner=$(stat -c %u "$POC_REPO")
  owner_name=$(getent passwd "$owner" | cut -d: -f1)
  [[ -n $owner_name && $owner != 0 ]] || return 1
  export_dir="$POC_EXPORT_BASE/live-${POC_STAGE##*.}"
  runuser -u "$owner_name" -- mkdir -p -- "$POC_EXPORT_BASE"
  runuser -u "$owner_name" -- mkdir -m 700 -- "$export_dir"
  tar -C "$POC_STAGE" --exclude='./docker-config' -cf - . | \
    runuser -u "$owner_name" -- tar --no-same-owner -xf - -C "$export_dir"
  printf 'User-readable evidence: %s\n' "$export_dir"
}

poc_finish() {
  local result=$?
  trap - EXIT
  # Repeated terminal signals must not interrupt resource teardown.
  trap '' INT TERM HUP
  set +e
  if [[ $POC_CLEANED == false ]]; then
    poc_cleanup || result=1
  fi
  # The final verifier runs after workload cleanup, so always cover it too.
  if ! poc_cleanup_tools; then
    result=1
    if [[ -f $POC_STAGE/cleanup.json ]]; then
      jq '.ok = false | .helperContainersRemoved = false' "$POC_STAGE/cleanup.json" \
        > "$POC_STAGE/cleanup-failed.json" && mv "$POC_STAGE/cleanup-failed.json" "$POC_STAGE/cleanup.json"
    fi
  fi
  if ((result != 0)) && [[ -s $POC_STAGE/result.json ]]; then
    jq '.status = "failed" | .failure = "helper did not complete or final cleanup failed"' "$POC_STAGE/result.json" \
      > "$POC_STAGE/result-failed.json" && mv "$POC_STAGE/result-failed.json" "$POC_STAGE/result.json"
  fi
  if [[ $POC_HOLD_STARTED == true ]]; then
    local session_status=closed
    ((result == 0)) || session_status=failed
    poc_session_receipt "$session_status" || result=1
  fi
  poc_export || result=1
  if ((result == 0)) && [[ -n $POC_SUCCESS ]]; then
    [[ ! -s $POC_STAGE/result.json ]] || cat "$POC_STAGE/result.json"
    printf '%s\n' "$POC_SUCCESS"
  fi
  printf 'Evidence retained: %s\n' "$POC_STAGE"
  if ((result != 0)); then
    printf 'POC FAILED or incomplete; inspect diagnostics and cleanup.json.\n' >&2
  fi
  exit "$result"
}
trap poc_finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

poc_tool() {
  local result=0
  local -a evidence_mount=()
  if [[ ${1:-} == verify ]]; then
    evidence_mount=(--mount "type=bind,src=$POC_STAGE,dst=/evidence,readonly")
  fi
  poc_docker run --rm --name "$POC_SESSION-tool" \
    --label "io.notty.egress-poc.session=$POC_SESSION" --label io.notty.egress-poc.role=tool \
    --pull never --network none --read-only --user 0:0 \
    --cap-drop ALL --security-opt no-new-privileges=true --pids-limit 64 --memory 512m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m --env TMPDIR=/tmp --env "NOSH_EGRESS_POC_RULE_COUNT=${NOSH_EGRESS_POC_RULE_COUNT:-1}" \
    --mount "type=bind,src=$POC_REPO/scripts/nosh-egress-poc.mjs,dst=/app/scripts/nosh-egress-poc.mjs,readonly" \
    --mount "type=bind,src=$POC_REPO/lib,dst=/app/lib,readonly" \
    --mount "type=bind,src=$POC_REPO/config,dst=/app/config,readonly" \
    --mount "type=bind,src=$POC_REPO/package.json,dst=/app/package.json,readonly" \
    "${evidence_mount[@]}" --entrypoint node "$POC_TOOL_IMAGE" /app/scripts/nosh-egress-poc.mjs "$@" || result=$?
  poc_cleanup_tools || result=1
  return "$result"
}

for POC_IMAGE in "$POC_CLIENT_IMAGE" "$POC_SERVER_IMAGE" "$POC_TOOL_IMAGE"; do
  [[ $(poc_docker image inspect --format '{{.Id}}' "$POC_IMAGE") == "$POC_IMAGE" ]] || poc_die 'required cached image unavailable'
done

if [[ $POC_MODE == --private ]]; then
  [[ -x $POC_LOADER && $(stat -Lc %u "$POC_LOADER") == 0 ]] || poc_die 'trusted installed loader unavailable'
  mount -t bpf -o nosuid,nodev,noexec,mode=700 nosh-egress-poc /sys/fs/bpf
  POC_BPFFS=true
  mkdir -m 700 /sys/fs/bpf/nosh-guard
  findmnt -T /sys/fs/bpf -o TARGET,FSTYPE,OPTIONS > "$POC_STAGE/mount.txt"
  "$POC_LOADER" health > "$POC_STAGE/health.json"
  jq -e --arg object "$POC_OBJECT" '.status == "healthy" and .objectDigest == $object and .mapAbi == 2 and .programAbi == 2' \
    "$POC_STAGE/health.json" >/dev/null || poc_die 'installed object differs from the verified POC object'
fi

POC_NETWORK_ID=$(poc_docker network create --internal --driver bridge \
  --label "io.notty.egress-poc.session=$POC_SESSION" "$POC_SESSION")
[[ $POC_NETWORK_ID =~ ^[a-f0-9]{64}$ ]] || poc_die 'invalid test network identity'
poc_docker network inspect "$POC_NETWORK_ID" > "$POC_STAGE/network.json"
jq -e 'length == 1 and .[0].Internal == true and .[0].EnableIPv6 == false' "$POC_STAGE/network.json" >/dev/null
POC_GATEWAY=$(jq -er '.[0].IPAM.Config[0].Gateway' "$POC_STAGE/network.json")

poc_create() {
  local role=$1
  shift
  POC_CREATED_ID=$(poc_docker create --pull never --name "$POC_SESSION-$role" \
    --network "$POC_NETWORK_ID" --read-only --user 1000:1000 \
    --cap-drop ALL --security-opt no-new-privileges=true --pids-limit 32 --memory 128m --cpus 1 \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --label "io.notty.egress-poc.session=$POC_SESSION" --label "io.notty.egress-poc.role=$role" \
    --log-driver json-file --log-opt max-size=1m --log-opt max-file=1 "$@")
  [[ $POC_CREATED_ID =~ ^[a-f0-9]{64}$ ]] || poc_die 'invalid test container identity'
  POC_CONTAINERS+=("$POC_CREATED_ID")
  poc_docker start "$POC_CREATED_ID" >/dev/null
}

POC_SERVER_CODE='const http = require("node:http"); const endpoint = process.argv[1]; http.createServer((req,res) => { console.log(JSON.stringify({endpoint,path:req.url})); res.writeHead(200,{"Content-Type":"text/plain","Connection":"close"}); res.end(endpoint.toUpperCase()); }).listen(8080,"0.0.0.0",() => console.log(JSON.stringify({endpoint,ready:true})));'
poc_create server-a --entrypoint node "$POC_SERVER_IMAGE" -e "$POC_SERVER_CODE" a
POC_SERVER_A=$POC_CREATED_ID
poc_create server-b --entrypoint node "$POC_SERVER_IMAGE" -e "$POC_SERVER_CODE" b
POC_SERVER_B=$POC_CREATED_ID
poc_create client --entrypoint /bin/sh "$POC_CLIENT_IMAGE" -c 'exec sleep 86400'
POC_CLIENT=$POC_CREATED_ID
for POC_SERVER in "$POC_SERVER_A" "$POC_SERVER_B"; do
  POC_READY=false
  for ((POC_ATTEMPT=0; POC_ATTEMPT<30; POC_ATTEMPT++)); do
    if poc_docker logs "$POC_SERVER" | jq -se 'any(.[]; .ready == true)' >/dev/null; then POC_READY=true; break; fi
    sleep 0.2
  done
  [[ $POC_READY == true ]] || poc_die 'HTTP server did not become ready'
done
POC_A=$(poc_docker inspect "$POC_SERVER_A" | jq -er --arg net "$POC_SESSION" '.[0].NetworkSettings.Networks[$net].IPAddress')
POC_B=$(poc_docker inspect "$POC_SERVER_B" | jq -er --arg net "$POC_SESSION" '.[0].NetworkSettings.Networks[$net].IPAddress')
poc_docker inspect "$POC_CLIENT" > "$POC_STAGE/client.json"
POC_CLIENT_PID=$(jq -er '.[0].State.Pid | select(. > 1)' "$POC_STAGE/client.json")
POC_CLIENT_START=$(poc_start_time "$POC_CLIENT_PID")
poc_docker exec "$POC_CLIENT" /usr/bin/curl --version > "$POC_STAGE/curl-version.txt"

poc_validate_client() {
  local member hierarchy controllers candidate memberships=0
  poc_docker inspect "$POC_CLIENT" | jq -e --arg id "$POC_CLIENT" --arg image "$POC_CLIENT_IMAGE" \
    --arg session "$POC_SESSION" --argjson pid "$POC_CLIENT_PID" \
    'length == 1 and .[0].Id == $id and .[0].Image == $image and .[0].State.Running == true
      and .[0].State.Pid == $pid and .[0].Config.Labels["io.notty.egress-poc.session"] == $session
      and .[0].Config.User == "1000:1000" and .[0].HostConfig.Privileged == false
      and .[0].HostConfig.ReadonlyRootfs == true and .[0].HostConfig.CapDrop == ["ALL"]
      and (.[0].Mounts | length) == 0 and (.[0].HostConfig.PortBindings // {} | length) == 0
      and (.[0].NetworkSettings.Networks | keys) == [$session]' >/dev/null || return 1
  [[ $(poc_start_time "$POC_CLIENT_PID") == "$POC_CLIENT_START" ]] || return 1
  while IFS=: read -r hierarchy controllers candidate; do
    if [[ $hierarchy == 0 && -z $controllers ]]; then
      member=$candidate
      memberships=$((memberships+1))
    fi
  done < "/proc/$POC_CLIENT_PID/cgroup"
  [[ $memberships == 1 && ( $member == */docker-"$POC_CLIENT".scope || $member == */docker/"$POC_CLIENT" ) ]] || return 1
  [[ $(readlink -f "/sys/fs/cgroup$member") == "/sys/fs/cgroup$member" ]] || return 1
  if [[ -n $POC_CGROUP_PATH ]]; then
    [[ $POC_CGROUP_PATH == "/sys/fs/cgroup$member" && $(stat -Lc %i "$POC_CGROUP_PATH") == "$POC_CGROUP_ID" ]] || return 1
  else
    POC_CGROUP_PATH="/sys/fs/cgroup$member"
    POC_CGROUP_ID=$(stat -Lc %i "$POC_CGROUP_PATH")
  fi
}
poc_validate_client || poc_die 'client runtime/cgroup identity mismatch'
POC_WORKSPACE_KEY=$(printf '%s' "$POC_SESSION" | sha256sum | cut -d' ' -f1)
jq -n --arg a "$POC_A" --arg b "$POC_B" --arg gateway "$POC_GATEWAY" \
  --arg clientImage "$POC_CLIENT_IMAGE" --arg clientId "$POC_CLIENT" --arg cgroupId "$POC_CGROUP_ID" \
  --argjson capacityRuleCount "${NOSH_EGRESS_POC_RULE_COUNT:-1}" \
  --arg objectDigest "$POC_OBJECT" --arg workspaceKey "$POC_WORKSPACE_KEY" --arg session "$POC_SESSION" \
  '{capacityRuleCount:$capacityRuleCount,a:$a,b:$b,gateway:$gateway,clientImage:$clientImage,clientId:$clientId,cgroupId:$cgroupId,
    objectDigest:$objectDigest,workspaceKey:$workspaceKey,phases:{
      allowA:{runId:($session+"-allowA"),pinRoot:("/sys/fs/bpf/nosh-guard/"+$session+"-allowA"),policyGeneration:"1"},
      allowB:{runId:($session+"-allowB"),pinRoot:("/sys/fs/bpf/nosh-guard/"+$session+"-allowB"),policyGeneration:"2"}}}' \
  > "$POC_STAGE/endpoints.json"
poc_tool policies "$POC_A" "$POC_B" "$POC_GATEWAY" > "$POC_STAGE/policies.json"
for POC_PHASE in allowA allowB; do
  mkdir -m 700 "$POC_STAGE/$POC_PHASE"
  jq --arg phase "$POC_PHASE" '.phases[$phase].policy' "$POC_STAGE/policies.json" > "$POC_STAGE/$POC_PHASE/policy.json"
  jq -jr --arg phase "$POC_PHASE" '.phases[$phase].manifest' "$POC_STAGE/policies.json" > "$POC_STAGE/$POC_PHASE/policy.manifest"
  [[ "sha256:$(sha256sum "$POC_STAGE/$POC_PHASE/policy.manifest" | cut -d' ' -f1)" == \
    "$(jq -er --arg phase "$POC_PHASE" '.phases[$phase].policyDigest' "$POC_STAGE/policies.json")" ]] || poc_die 'manifest digest mismatch'
done

poc_probe() {
  local phase=$1 endpoint=$2 address raw code http_code body
  [[ $endpoint == a ]] && address=$POC_A || address=$POC_B
  poc_validate_client || poc_die 'client changed before probe'
  if raw=$(poc_docker exec "$POC_CLIENT" /usr/bin/curl -q --proxy '' --noproxy '*' \
      --proto '=http' --connect-timeout 2 --max-time 4 --silent --show-error --fail \
      --write-out $'\n%{http_code}' "http://$address:8080/$phase/$endpoint" \
      2> "$POC_STAGE/$phase-$endpoint.stderr"); then code=0; else code=$?; fi
  http_code=${raw##*$'\n'}
  body=${raw%$'\n'*}
  jq -cn --arg phase "$phase" --arg endpoint "$endpoint" --arg address "$address" \
    --argjson exitCode "$code" --arg httpCode "$http_code" --arg body "$body" \
    --rawfile error "$POC_STAGE/$phase-$endpoint.stderr" \
    '{phase:$phase,endpoint:$endpoint,address:$address,port:8080,exitCode:$exitCode,httpCode:$httpCode,body:$body,error:$error}' \
    | tee -a "$POC_STAGE/probes.jsonl"
}

printf 'Baseline: both local HTTP endpoints must succeed.\n'
poc_probe baseline a
poc_probe baseline b
jq -se 'length == 2 and all(.[]; .exitCode == 0 and .httpCode == "200" and .body == (.endpoint | ascii_upcase))' \
  "$POC_STAGE/probes.jsonl" >/dev/null || poc_die 'baseline connectivity failed'
if [[ $POC_MODE == --baseline ]]; then
  poc_cleanup || poc_die 'baseline cleanup failed'
  POC_SUCCESS='BASELINE PASSED. No BPF was loaded or attached.'
  exit 0
fi

poc_session_receipt() {
  local status=$1 cleanup=null
  [[ ! -f $POC_STAGE/cleanup.json ]] || cleanup=$(<"$POC_STAGE/cleanup.json")
  jq -n --arg status "$status" --arg phase "$POC_HOLD_PHASE" --arg clientId "$POC_CLIENT" \
    --arg cgroupId "$POC_CGROUP_ID" --arg policyDigest "$POC_POLICY_DIGEST" --arg pinRoot "$POC_HELD_PIN_ROOT" \
    --arg allowedUrl "$POC_ALLOWED_URL" --arg deniedUrl "$POC_DENIED_URL" \
    --arg reason "$POC_HOLD_STOP_REASON" --arg policyPath "$POC_STAGE/$POC_HOLD_PHASE/policy.json" \
    --argjson cleanup "$cleanup" \
    '{schemaVersion:1,kind:"NoshEgressPocHeldSession",status:$status,phase:$phase,
      checkedAt:(now|todateiso8601),clientId:$clientId,cgroupId:$cgroupId,policyDigest:$policyDigest,
      pinRoot:$pinRoot,allowedUrl:$allowedUrl,deniedUrl:$deniedUrl,policyPath:$policyPath,
      initialChecksPassed:true,stopReason:$reason,cleanup:$cleanup,
      captureCompleteness:"not assessed; closed reports successful teardown",
      scope:"Supervised diagnostic session; not the six-probe acceptance result"}' \
    > "$POC_STAGE/held-session.tmp" || return 1
  mv "$POC_STAGE/held-session.tmp" "$POC_STAGE/held-session.json"
}

poc_monitor_hold() {
  local size file
  [[ $(poc_start_time "$POC_COLLECTOR") == "$POC_COLLECTOR_START" ]] || return 1
  poc_validate_client || return 1
  timeout --kill-after=2s 5s "$POC_LOADER" status --pin-root "$POC_PIN_ROOT" \
    > "$POC_STAGE/$POC_PHASE/last-status.json" 2>> "$POC_STAGE/$POC_PHASE/monitor.log" || return 1
  jq -e --slurpfile expected "$POC_STAGE/$POC_PHASE/status.json" \
    'del(.timestampUnixNs) == ($expected[0] | del(.timestampUnixNs))' \
    "$POC_STAGE/$POC_PHASE/last-status.json" >/dev/null || return 1
  for file in events.jsonl collector-status.jsonl diagnostics.log monitor.log; do
    size=$(stat -c %s "$POC_STAGE/$POC_PHASE/$file") || return 1
    if ((size > 64 * 1024 * 1024)); then
      POC_HOLD_STOP_REASON=evidence-size-limit
      return 1
    fi
  done
}

poc_hold() {
  local allowed_endpoint=a denied_endpoint=b allowed_address=$POC_A denied_address=$POC_B ready=false attempt
  if [[ $POC_PHASE == allowB ]]; then
    allowed_endpoint=b; denied_endpoint=a; allowed_address=$POC_B; denied_address=$POC_A
  fi
  jq -se --arg phase "$POC_PHASE" --arg allowed "$allowed_endpoint" --arg denied "$denied_endpoint" \
    '[.[] | select(.phase == $phase)] | length == 2
      and any(.[]; .endpoint == $allowed and .exitCode == 0 and .httpCode == "200" and .body == ($allowed|ascii_upcase))
      and any(.[]; .endpoint == $denied and .exitCode == 7 and .httpCode == "000" and .body == "")' \
    "$POC_STAGE/probes.jsonl" >/dev/null || poc_die 'held policy failed its initial probes'
  for ((attempt=0; attempt<50; attempt++)); do
    if jq -se --arg cg "$POC_CGROUP_ID" --arg generation "$POC_GENERATION" \
        --arg allowed "$allowed_address" --arg denied "$denied_address" \
        '[.[] | select(.recordKind == "decision" and .cgroupId == $cg and .policyGeneration == $generation
          and .hook == 1 and .family == 4 and .protocol == 6 and .destinationPort == 8080 and .enforcementApplied == true)]
          | any(.[]; .destinationAddress == $allowed and .verdict == "allow" and .decisionClass == "policy-allow" and .reason == "static-policy")
            and any(.[]; .destinationAddress == $denied and .verdict == "deny" and .decisionClass == "policy-deny" and .reason == "default-deny")' \
        "$POC_STAGE/$POC_PHASE/events.jsonl" >/dev/null 2>/dev/null; then ready=true; break; fi
    sleep 0.1
  done
  [[ $ready == true ]] || poc_die 'held policy has no matching kernel allow/deny evidence'
  poc_monitor_hold || poc_die 'held policy failed its initial supervision check'
  POC_ALLOWED_URL="http://$allowed_address:8080/manual/$allowed_endpoint"
  POC_DENIED_URL="http://$denied_address:8080/manual/$denied_endpoint"
  POC_HELD_PIN_ROOT=$POC_PIN_ROOT
  POC_HOLD_STARTED=true
  poc_session_receipt active || poc_die 'could not write the initial held-session receipt'
  printf '\nPolicy %s is attached. Keep this host terminal open.\n' "$POC_PHASE"
  printf 'In another HOST terminal, enter the container with:\n\n'
  printf 'docker --host unix:///var/run/docker.sock exec -it --user 1000:1000 --env %q --env %q %q /bin/sh\n' \
    "ALLOW_URL=$POC_ALLOWED_URL" "DENY_URL=$POC_DENIED_URL" "$POC_CLIENT"
  printf '\nInside the container:\n'
  printf '%s\n' '  curl --noproxy '\''*'\'' --max-time 3 "$ALLOW_URL"' \
    '  curl --noproxy '\''*'\'' --max-time 3 "$DENY_URL"'
  printf '\nShell exit only disconnects. Ctrl-C HERE stops this holder and cleans up.\n'
  printf 'Policy JSON: %s/%s/policy.json\n' "$POC_STAGE" "$POC_PHASE"
  trap 'POC_HOLD_STOP=true; POC_HOLD_STOP_REASON=SIGINT' INT
  trap 'POC_HOLD_STOP=true; POC_HOLD_STOP_REASON=SIGTERM' TERM
  trap 'POC_HOLD_STOP=true; POC_HOLD_STOP_REASON=SIGHUP' HUP
  while [[ $POC_HOLD_STOP == false ]]; do
    if ! poc_monitor_hold; then
      [[ $POC_HOLD_STOP == false ]] || break
      [[ -n $POC_HOLD_STOP_REASON ]] || POC_HOLD_STOP_REASON=supervision-failed
      poc_docker pause "$POC_CLIENT" >/dev/null 2>&1 || true
      poc_die 'held client, collector, or policy changed; stopping the session'
    fi
    [[ $POC_HOLD_STOP == false ]] || break
    if ! poc_session_receipt active; then
      [[ $POC_HOLD_STOP == false ]] || break
      poc_die 'could not update the held-session receipt'
    fi
    sleep 2 || true
  done
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
}

POC_PHASES=(allowA allowB)
[[ -z $POC_HOLD_PHASE ]] || POC_PHASES=("$POC_HOLD_PHASE")
for POC_PHASE in "${POC_PHASES[@]}"; do
  printf 'Enforcement phase: %s\n' "$POC_PHASE"
  if [[ $(poc_docker inspect --format '{{.State.Paused}}' "$POC_CLIENT") != true ]]; then
    poc_docker pause "$POC_CLIENT" >/dev/null
  fi
  poc_validate_client || poc_die 'client changed before attachment'
  POC_PIN_ROOT=$(jq -er --arg phase "$POC_PHASE" '.phases[$phase].pinRoot' "$POC_STAGE/endpoints.json")
  POC_GENERATION=$(jq -er --arg phase "$POC_PHASE" '.phases[$phase].policyGeneration' "$POC_STAGE/endpoints.json")
  POC_RUN_ID=$(jq -er --arg phase "$POC_PHASE" '.phases[$phase].runId' "$POC_STAGE/endpoints.json")
  POC_POLICY_DIGEST=$(jq -er --arg phase "$POC_PHASE" '.phases[$phase].policyDigest' "$POC_STAGE/policies.json")
  (
    # Bound held-session collector output even between supervision checks.
    [[ -z $POC_HOLD_PHASE ]] || ulimit -f 131072
    exec "$POC_LOADER" run --cgroup "$POC_CGROUP_PATH" --cgroup-id "$POC_CGROUP_ID" --mode enforce \
    --policy "$POC_STAGE/$POC_PHASE/policy.manifest" --policy-digest "$POC_POLICY_DIGEST" \
    --pin-root "$POC_PIN_ROOT" --generation "$POC_GENERATION" --run-id "$POC_RUN_ID" \
    --image-digest "$POC_CLIENT_IMAGE" --workspace-key "$POC_WORKSPACE_KEY" --status-fd 3
  ) > "$POC_STAGE/$POC_PHASE/events.jsonl" 3> "$POC_STAGE/$POC_PHASE/collector-status.jsonl" \
    2> "$POC_STAGE/$POC_PHASE/diagnostics.log" &
  POC_COLLECTOR=$!
  POC_COLLECTOR_START=$(poc_start_time "$POC_COLLECTOR") || poc_die 'loader exited during startup'
  POC_READY=false
  for ((POC_ATTEMPT=0; POC_ATTEMPT<100; POC_ATTEMPT++)); do
    [[ $(poc_start_time "$POC_COLLECTOR") == "$POC_COLLECTOR_START" ]] || poc_die 'loader exited before readiness'
    if jq -se 'any(.[]; .recordKind == "status" and .status == "ready")' \
        "$POC_STAGE/$POC_PHASE/collector-status.jsonl" >/dev/null 2>/dev/null; then POC_READY=true; break; fi
    sleep 0.1
  done
  [[ $POC_READY == true ]] || poc_die 'loader readiness timed out'
  "$POC_LOADER" status --pin-root "$POC_PIN_ROOT" > "$POC_STAGE/$POC_PHASE/status.json"
  jq -e --arg cg "$POC_CGROUP_ID" --arg digest "$POC_POLICY_DIGEST" --arg object "$POC_OBJECT" \
    --arg generation "$POC_GENERATION" --arg run "$POC_RUN_ID" --arg image "$POC_CLIENT_IMAGE" \
    --arg workspace "$POC_WORKSPACE_KEY" --arg pin "$POC_PIN_ROOT" \
    '.status == "ready" and .mode == "enforce" and .cgroupId == $cg and .attachedPrograms == 6
      and .policyDigest == $digest and .objectDigest == $object and .pinRoot == $pin
      and .mapAbi == 2 and .programAbi == 2 and .containmentCount == 1
      and .attestation.targetCgroupId == $cg and .attestation.policyGeneration == $generation
      and .attestation.runId == $run and .attestation.imageDigest == $image and .attestation.workspaceKey == $workspace
      and (.attestation.linkIds | length) == 6 and (.attestation.mapIds | length) == 12' \
    "$POC_STAGE/$POC_PHASE/status.json" >/dev/null || poc_die 'attachment identity mismatch'
  poc_docker unpause "$POC_CLIENT" >/dev/null
  poc_probe "$POC_PHASE" a
  poc_probe "$POC_PHASE" b
  if [[ -n $POC_HOLD_PHASE ]]; then
    poc_hold
  fi
  poc_docker pause "$POC_CLIENT" >/dev/null
  poc_stop_collector || poc_die 'collector did not shut down cleanly'
  "$POC_LOADER" snapshot --pin-root "$POC_PIN_ROOT" > "$POC_STAGE/$POC_PHASE/snapshot.jsonl"
  "$POC_LOADER" detach --pin-root "$POC_PIN_ROOT" > "$POC_STAGE/$POC_PHASE/detach.json"
  [[ ! -e $POC_PIN_ROOT ]] || poc_die 'pin root remains after detach'
  POC_PIN_ROOT=''
  # Keep it gated across detach -> next attach, and through final cleanup.
done
poc_cleanup || poc_die 'cleanup was not fully verified'
if [[ -n $POC_HOLD_PHASE ]]; then
  POC_SUCCESS='HELD SESSION CLOSED: policy detached and test resources removed.'
  exit 0
fi
poc_tool verify /evidence > "$POC_STAGE/result.json"
POC_SUCCESS='LIVE ENFORCEMENT POC PASSED: baseline, allow-A, allow-B, evidence, cleanup.'
