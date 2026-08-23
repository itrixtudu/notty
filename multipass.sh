#!/usr/bin/env bash

if [[ "${DOCKER_CONTAINER:-}" != "1" ]] && [[ ! -f /.dockerenv ]]; then
  echo "multipass.sh: refusing to run npm on the host; launch it inside Nosh" >&2
  exit 1
fi

OTP1=`openssl rand -hex 8 | fold -w4 | head -n1`
OTP2=`openssl rand -hex 8 | fold -w4 | head -n1`
OTP3=`openssl rand -hex 8 | fold -w4 | head -n1`

echo "codex:3000:$OTP1"
echo "gemini::3001:$OTP2"
echo "claude::3002:$OTP3"

PORT=3000 NOTTY_MCP_SPAWN_OTP=$OTP1 npm run dev &
PORT=3001 NOTTY_MCP_SPAWN_OTP=$OTP2 npm run dev &
PORT=3002 NOTTY_MCP_SPAWN_OTP=$OTP3 npm run dev &

# npm i @anthropic-ai/claude-code@latest
# npm i @openai/codex@latest
# npm i @google/gemini-cli@latest

echo "claude mcp add collab3 -- node collab3.js mcp"
echo "claude --allow-dangerously-skip-permissions"

echo "codex mcp add collab3 -- node collab3.js mcp"
echo "codex --full-auto"

echo "gemini mcp add collab3 -- node collab3.js mcp"
echo "gemini -y"

echo "source \$(codex completion bash)"
echo "source \$(gemini completion bash)"
echo "source \$(claude completion bash)"



tail -f /dev/null
