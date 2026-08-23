#!/usr/bin/env bash
set -euo pipefail

# Minimal harness to exercise MCP tools with terminal_uuid only.
# The long hash printed after docker run is the container ID.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

source "$ROOT/start_oauth.sh" 2>/dev/null || true

NAME="${NAME:-ntty}"
IMAGE="${IMAGE:-ntty}"
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HTTP_TARGET="${HTTP_TARGET:-$BASE_URL/mcp}"
SSE_TARGET="${SSE_TARGET:-$BASE_URL/mcp/sse}"
OTP="${NOTTY_MCP_SPAWN_OTP:-otptest}"
OTP_TTL="${NOTTY_MCP_SPAWN_OTP_TTL_SECONDS:-3600}"

TOKEN=""
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
    docker run --name "$NAME" --hostname "$NAME" --rm -d -p 3000:3000 \
      -e NOTTY_MCP_SPAWN_OTP="$OTP" \
      -e NOTTY_MCP_SPAWN_OTP_TTL_SECONDS="$OTP_TTL" \
      -e NOTTY_OAUTH_ENABLED \
      -e NOTTY_OAUTH_CLIENT_ID \
      -e NOTTY_OAUTH_CLIENT_SECRET \
      -e NOTTY_OAUTH_BOOT_TOKEN \
      -e NOTTY_OAUTH_TTL_SECONDS \
      -e NOTTY_OAUTH_TOKEN_PATH \
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

maybe_fetch_token() {
  if [ "${NOTTY_OAUTH_ENABLED:-}" != "true" ]; then
    echo "OAuth not enabled; running without bearer token."
    return
  fi
  TOKEN=$(
    curl -sf -u "$NOTTY_OAUTH_CLIENT_ID:$NOTTY_OAUTH_CLIENT_SECRET" \
      -d 'grant_type=client_credentials' \
      "$BASE_URL/oauth/token" \
    | jq -r '.access_token // empty'
  )
  if [ -z "$TOKEN" ]; then
    echo "OAuth enabled but token missing; continuing without Authorization header."
  else
    echo "bearer_token_acquired"
  fi
}

token_args() {
  if [ -n "$TOKEN" ]; then
    echo "--token $TOKEN"
  fi
}

run_basic_flow() {
  local extra_args
  extra_args=()
  if [ -n "$TOKEN" ]; then
    extra_args+=(--token "$TOKEN")
  fi

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
  maybe_fetch_token
  run_basic_flow
}

main "$@"
