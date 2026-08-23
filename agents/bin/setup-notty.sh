#!/usr/bin/env bash

codex mcp remove notty
codex mcp remove notty


codex mcp add notty --url http://localhost:3000/mcp
gemini mcp add -t sse notty http://localhost:3000/sse
