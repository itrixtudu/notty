#!/usr/bin/env bash

codex mcp remove notty
gemini mcp remove notty
gemini mcp remove collab
codex mcp remove collab
codex mcp remove puppeteer
codex mcp remove chrome-devtools
codex mcp remove ghidra

#codex mcp add chrome-devtools -- npx chrome-devtools-mcp@1.5.0 --slim --headless
#codex mcp add chrome-devtools -- npx -y chrome-devtools-mcp@1.5.0

codex mcp add notty --url http://localhost:3000/mcp
gemini mcp add -t sse notty http://localhost:3000/sse



codex mcp add collab --url "${COLLAB_MCP_URL:-http://127.0.0.1:1337/mcp}"
gemini mcp add -t stdio collab node collab.cjs mcp
