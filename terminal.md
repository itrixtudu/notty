# Terminal Session Overview

## Spawn Entry Points
- [`lib/terminalManager.js`](lib/terminalManager.js) exposes `spawnTerminal()`,
  the shared helper that launches a PTY with `pty.spawn()`.
- **MCP transports**
  - [`lib/mcpTools.js`](lib/mcpTools.js) defines the `spawn_terminal` tool
    that delegates to `spawnTerminal()`.
  - [`lib/createMcpServer.js`](lib/createMcpServer.js) wires the tool into the
    MCP server, while [`server.js`](server.js) and
    [`pages/api/mcp/call.js`](pages/api/mcp/call.js) expose HTTP paths.
- **HTTP/REST transports**
  - [`lib/terminalHttpApi.js`](lib/terminalHttpApi.js) and
    [`pages/api/terminals/index.js`](pages/api/terminals/index.js) handle
    terminal creation for the integrated and Next.js paths.
- **WebSocket**
  - [`lib/terminalWsHandlers.js`](lib/terminalWsHandlers.js) attaches to an
    existing session rather than spawning one.
- **Local helpers**
  - [`rsh`](rsh) can create a default local session when none exists.
  - [`main.js`](main.js) is a manual local PTY harness.

## Opt-in per-terminal locking

Terminal sessions do not force `vlock`. `spawnTerminal()` uses the requested
shell when one is supplied and otherwise defaults to Bash on Unix-like hosts
or PowerShell on Windows. Session metadata reports the selected shell.

The Nosh image includes `vlock` as an opt-in convenience. For a running
persistent legacy container, set the container account's Unix password from
the host with `./scripts/nosh.sh set-login-password`, then run `vlock` inside the PTY
you want to pause. That password is intended for `vlock`, but it is the
account's general Unix password and another PAM consumer could also accept it.
Guard-managed runners reject the setup command.

`vlock` protects only its current PTY. It does not lock other tmux sessions,
the browser, Notty APIs, agents, the container, or the host. It is unrelated
to the separate lockdown UI and route controls.

## Terminal Type Defaults
- `spawnTerminal()` defaults to `terminalType = 'vt100'` when no type is
  supplied.
- The Next.js terminal API defaults UI sessions to `xterm`.
- MCP callers default to `vt100` and can request `xterm`, `ansi`, or `ascii`.
- `mapTerminalTypeToPtyName()` translates those logical types into the `TERM`
  value used for the spawned PTY.

## OAuth 2.1 for MCP

- HTTP MCP uses authorization-code OAuth by default, with public dynamic client
  registration, PKCE S256, exact resource audiences, one-hour access tokens,
  and rotating refresh tokens. The consent page uses the UI's Basic
  authentication unless `--noauth` is selected on a loopback-only launch.
- OAuth tokens and spawn OTPs are stored only as hashes in the workspace auth
  database; client and grant metadata is persisted alongside them. Secrets are
  never logged, written to URLs, or accepted from query strings.
- Add the exact `/mcp` URL to Codex, run `codex mcp login notty`, and approve
  the browser consent page. Use the launcher OTP only as the `otp` argument of
  a terminal-spawning MCP call.
- `--no-otp-auth` is the local OTP-only workflow: MCP requests need no HTTP
  `Authorization` header, while every external spawn still consumes one OTP.
- `nosh auth otp` mints a fresh workspace OTP locally and shows it once; HTTP
  minting remains disabled in OTP-only mode.
