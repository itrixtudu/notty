# Interface Architecture Overview

This document summarizes the code that powers Notty's different surfaces:

- the HTML control panel (Next.js UI + REST helpers)
- the Model Context Protocol (MCP) endpoints exposed over plain HTTP or Server-Sent Events (SSE)
- the WebSocket stream that backs the live terminal view

Although each transport exposes a different experience, they are all thin wrappers around the same terminal runtime and MCP tooling helpers. Understanding what is shared makes it easier to extend Notty without duplicating logic.

## Shared terminal runtime

`lib/terminalManager.js` is the single source of truth for spawning pseudo-terminals, buffering output, wiring resize events, and terminating sessions.【F:lib/terminalManager.js†L1-L209】【F:lib/terminalManager.js†L209-L318】 Every interface calls into this module instead of speaking to `node-pty` directly.

Key capabilities exported here (spawn, read, write, resize, kill, subscribe, inspect) are consumed by both the REST and MCP layers, which keeps session semantics consistent regardless of transport.

## Shared MCP surface

The MCP server is constructed once via `createMcpServer`, which registers the `listTools`/`callTool` handlers against the same `toolDefinitions` array and `callTool` dispatcher used everywhere else.【F:lib/createMcpServer.js†L1-L35】 Those tool definitions live in `lib/mcpTools.js` and delegate each tool action back to the terminal manager helpers (spawn, write, read, resize, etc.).【F:lib/mcpTools.js†L1-L117】 As a result, the tooling that MCP clients see is identical whether they connect over stdio, HTTP, or SSE.

`server.js` reuses that same MCP server factory in each mode: stdio (`startStdioServer`), standalone SSE, and the combined Next.js server.【F:server.js†L1-L126】 The only differences are the transports that wrap the server.

## HTML/Next.js interface

When Notty runs in Next.js mode, `server.js` bootstraps Express, attaches the REST API from `registerTerminalHttpRoutes`, and then hands control to Next for the React UI.【F:server.js†L90-L209】 The React pages call those REST routes to create/list/kill terminals (see `pages/index.js` for the control surface).【F:pages/index.js†L1-L120】

For live terminal output the browser calls `/api/ws`, an Express helper that reports the WebSocket endpoint registered by `registerExternalWsServer`.【F:server.js†L209-L278】 The `components/XtermRenderer.js` widget then resolves that URL, opens the socket, and translates user keystrokes into `input`/`resize` messages while streaming `output` frames back into xterm.js.【F:components/XtermRenderer.js†L1-L196】【F:components/XtermRenderer.js†L196-L276】

Set `NOTTY_LOCKDOWN=true` to collapse that REST surface: the Express router short-circuits the terminal list/spawn/kill/read/write/resize handlers with `403` responses while still publishing a minimal `/health` probe that reports whether lockdown is active.【F:lib/terminalHttpApi.js†L27-L93】 The Next.js API handlers share the same guard, so `/api/terminals` (and the nested read/write/resize routes) also return `403` without affecting `/api/ws` or any MCP HTTP/SSE endpoints.【F:pages/api/terminals/index.js†L1-L28】【F:pages/api/terminals/[id]/read.js†L1-L27】

## MCP over HTTP or SSE

`lib/mcpHttpServer.js` is the glue that lets the same MCP server answer HTTP requests (`StreamableHTTPServerTransport`) or long-lived SSE sessions (`SSEServerTransport`).【F:lib/mcpHttpServer.js†L1-L101】 It tracks active sessions, instantiates the shared MCP server on demand, and routes `/message` POSTs back into the SSE transport.【F:lib/mcpHttpServer.js†L101-L186】 Express routes in `server.js` expose this as `/mcp`, `/mcp/sse`, and `/mcp/message` when `MCP_TRANSPORT=sse` is enabled, while still sharing the same MCP tool definitions and session map as the HTTP transport.【F:server.js†L126-L209】

The standalone SSE mode (`startStandaloneSseServer`) uses the exact same helpers, only without the Next.js layer, so browser tooling and headless MCP clients stay in sync.【F:server.js†L38-L88】

## WebSocket terminal streaming

Regardless of how the HTTP layer is configured, live terminal streaming always goes through `lib/terminalWsHandlers.js`. That module listens for connections, rehydrates buffered history from the terminal manager, subscribes to future output, and forwards `input`/`resize` events back to the same runtime helpers.【F:lib/terminalWsHandlers.js†L1-L127】 `registerExternalWsServer` simply wires those handlers into either the Express-created `WebSocketServer` (Next.js mode) or a standalone server, while keeping the resolved URL available to `/api/ws`.【F:lib/standaloneWsServer.js†L1-L83】

## Layer interplay summary

- **Terminal lifecycle** — One implementation (`terminalManager`) powers REST, WebSocket, and MCP commands, so all transports see the same session IDs, buffering, and cleanup semantics.
- **MCP tooling** — `createMcpServer` + `mcpTools` give every MCP transport (stdio, HTTP, SSE) the same method surface without duplicating tool registration.
- **Web UI plumbing** — The Next.js UI depends only on the REST + WebSocket endpoints exposed by `server.js`, which themselves are thin shells over the shared terminal and MCP helpers.
- **SSE vs HTTP** — `mcpHttpServer` adapts the shared MCP server to whichever streaming mechanism is requested, but never re-implements tool logic.

When adding new terminal capabilities, implement them once inside `terminalManager` and surface them through `mcpTools`. The HTML, SSE, and WebSocket layers will inherit the behavior automatically through these shared modules.
