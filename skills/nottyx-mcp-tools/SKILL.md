---
name: nottyx-mcp-tools
description: Use when working in the NottyX repo to expose, extend, or call the MCP terminal toolset implemented in `lib/mcpTools.js` (spawn_terminal/write_terminal/read_terminal/open_reader/read_delta/close_reader/resize_terminal/kill_terminal/list_terminals/set_terminal_type), including one-time terminal spawn OTPs and terminal_uuid handling, and when automating TUI apps like Durdraw using these tools (see `references/durdraw-notes.md` for the observed keymap).
---

# NottyX MCP Tools (Full Toolset)

## Overview

Use NottyX’s “full” MCP toolset to spawn/manage terminal sessions, write input, and read output. Use the same primitives to automate TUIs (including Durdraw) by sending key sequences.

## Call the tools (client workflow)

1. Call `spawn_terminal` and store `terminal_uuid`.
2. Call `write_terminal` with `terminal_uuid` + `data` (use `\\r\\n` to press Enter).
3. Call `read_terminal` for snapshots, or `open_reader` + `read_delta` for streaming.
4. Call `resize_terminal` / `set_terminal_type` as needed; call `kill_terminal` when done.

### Streaming reads

- Prefer `open_reader` + `read_delta` for long-running commands; close it with `close_reader`.
- Use `include_history: true` only when you need the full buffered output from session start.

## OTP-protected spawn mode

Terminal spawning requires a one-time OTP by default; only an explicit `--no-otp`
launch disables this check.

- Pass a fresh launcher/operator OTP as the `otp` argument to `spawn_terminal`.
- Use `terminal_uuid` for every other tool call (`terminal_id` is rejected in this mode).
- Non-spawn tools, including `list_terminals`, do not consume an OTP.

## Durdraw via terminal tools

- Start Durdraw by running `durdraw ...` via `write_terminal`, then drive it with key sequences.
- Use the observed keymap in `references/durdraw-notes.md` for menu/navigation/save/export workflows.

### Send key sequences

- Represent Escape as `\\u001b` in JSON.
- `write_terminal` decodes `\\n`, `\\r`, `\\t`, and `\\\\` (so `\\r\\n` is the simplest “press Enter”).
- Prefer Durdraw’s `esc-1` … `esc-0` shortcuts over raw F-keys when possible (more portable).

Examples (encode as `data` strings for `write_terminal`):

- `esc-q` (quit): `\\u001bq`
- `esc-s` (save): `\\u001bs`
- `tab` (color picker): `\\t`
- `up` arrow: `\\u001b[A`
- `esc-up` (Escape prefix + up arrow): `\\u001b\\u001b[A`

## Extend the toolset (repo workflow)

When adding/changing tools in this repo:

- Edit tool definitions + implementation in `lib/mcpTools.js`.
- Ensure `lib/mcpToolset.js` is in `full` mode (default) when you need these tools (or set `NOTTY_MCP_TOOLSET=full`).
- Keep schema + behavior consistent with the existing `callTool()` switch (return JSON text on success; set `isError: true` on failures).

## Resources

- `references/durdraw-notes.md`: Observed Durdraw keymap + workflows.
