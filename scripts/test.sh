#!/usr/bin/env bash
set -euo pipefail

# Minimal harness to exercise MCP tools with terminal_uuid only.
# The long hash printed after docker run is the container ID.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NAME="${NAME:-ntty}"
IMAGE="${IMAGE:-ntty}"
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HTTP_TARGET="${HTTP_TARGET:-$BASE_URL/mcp}"
SSE_TARGET="${SSE_TARGET:-$BASE_URL/mcp/sse}"
OTP="${NOTTY_MCP_SPAWN_OTP:-otptest}"
OTP_TTL="${NOTTY_MCP_SPAWN_OTP_TTL_SECONDS:-3600}"

TERMINAL_UUID=""

say() {
  echo
  echo "=== $*"
}

call_tool() {
  local target="$1"
  local tool="$2"
  local payload="${3:-{}}"
  shift 3 || true
  node scripts/call-tool.js "$target" "$tool" "$payload" --json "$@"
}

list_tools() {
  node scripts/list-tools.js "$1" --json "$@"
}

start_container() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  CID=$(
    docker run --name "$NAME" --hostname "$NAME" --rm -d -p 127.0.0.1:3000:3000 \
      -e NOTTY_MCP_SPAWN_OTP="$OTP" \
      -e NOTTY_MCP_SPAWN_OTP_TTL_SECONDS="$OTP_TTL" \
      -e NOTTY_NO_OTP_AUTH=true \
      -e NOTTY_NOAUTH=true \
      -e NOTTY_NO_OAUTH=true \
      -e NOTTY_OAUTH_ENABLED=false \
      -e NOTTY_BASIC_AUTH_ENABLED=false \
      -e NOTTY_MCP_SPAWN_OTP_ENABLED=true \
      -e NOTTY_LOOPBACK_PUBLICATION=true \
      -e NOTTY_PUBLIC_ORIGIN="$BASE_URL" \
      "$IMAGE"
  )
  echo "container_id=$CID"
  trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
}

wait_for_ready() {
  for _ in $(seq 1 30); do
    if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "server not ready on $BASE_URL"
}

run_basic_flow() {
  local extra_args
  extra_args=()

  say "list tools"
  list_tools "$HTTP_TARGET" "${extra_args[@]}" || true

  say "spawn_terminal with OTP (terminal_uuid only)"
  output=$(call_tool "$HTTP_TARGET" spawn_terminal "{\"otp\":\"$OTP\"}" "${extra_args[@]}" || true)
  echo "$output"
  TERMINAL_UUID=$(echo "$output" | jq -r '.content[0].text | fromjson | .terminal_uuid')
  if [ -z "$TERMINAL_UUID" ] || [ "$TERMINAL_UUID" = "null" ]; then
    echo "failed to capture terminal_uuid"
    return
  fi
  echo "terminal_uuid=$TERMINAL_UUID"

  say "write/read over HTTP (terminal_uuid)"
  call_tool "$HTTP_TARGET" write_terminal "{\"terminal_uuid\":\"$TERMINAL_UUID\",\"data\":\"echo http-flow\\r\"}" "${extra_args[@]}" || true
  sleep 1
  call_tool "$HTTP_TARGET" read_terminal "{\"terminal_uuid\":\"$TERMINAL_UUID\"}" "${extra_args[@]}" || true

  say "write/read over SSE (terminal_uuid)"
  call_tool "$SSE_TARGET" write_terminal "{\"terminal_uuid\":\"$TERMINAL_UUID\",\"data\":\"echo sse-flow\\r\"}" "${extra_args[@]}" || true
  sleep 1
  call_tool "$SSE_TARGET" read_terminal "{\"terminal_uuid\":\"$TERMINAL_UUID\"}" "${extra_args[@]}" || true

  say "kill_terminal via terminal_uuid"
  call_tool "$HTTP_TARGET" kill_terminal "{\"terminal_uuid\":\"$TERMINAL_UUID\"}" "${extra_args[@]}" || true
}

main() {
  start_container
  wait_for_ready
  run_basic_flow
}

main "$@"
