# Codex with an Ollama model

This example starts the installed `codex` CLI with an isolated model provider
backed by an external Ollama daemon. It reuses Notty's production preflight and
loopback compatibility relay rather than writing `~/.codex/config.toml` or
calling `ollama launch`.

## Requirements

- Run from this repository checkout with Node.js, `curl`, and `codex` on
  `PATH`. No package installation is needed.
- Set `OLLAMA_HOST` to a reachable Ollama client origin. Do not use a daemon
  bind address such as `0.0.0.0`.
- Install the selected model on that daemon first. Its `/api/show` response
  must advertise the `tools` capability. The example never pulls a model.

The default lean Nosh image is sufficient because the Ollama CLI and model
files are not needed inside this process. Build `TARGET=ollama` only when you
also want the `ollama` command in the image.

## Interactive use

From the repository root:

```bash
OLLAMA_HOST=http://127.0.0.1:11434 \
  node examples/codex-ollama/run.cjs --model qwen3:4b
```

With no trailing Codex arguments, the example opens the Codex TUI with a
read-only sandbox and approvals disabled. From a container, use an address
that reaches the daemon host rather than container-local `127.0.0.1`.

## One-shot use

Arguments after `--` are passed directly to Codex and replace the safe
interactive defaults:

```bash
OLLAMA_HOST=http://127.0.0.1:11434 \
  node examples/codex-ollama/run.cjs --model qwen3:4b -- \
  exec --ephemeral --skip-git-repo-check --sandbox read-only \
  'Inspect package.json and reply with only the package name.'
```

Use `--endpoint`, `--codex-bin`, `--curl-bin`, `--runtime-dir`, or
`--timeout-ms` when their environment defaults are unsuitable. Run
`node examples/codex-ollama/run.cjs --help` for the complete syntax.

## What it demonstrates

1. `/api/tags` and `/api/show` verify that the requested model is installed
   and tool-capable.
2. A private, per-launch model catalog and collision-resistant Codex provider
   are generated without mutating user configuration.
3. Codex uses a Responses provider through a random loopback relay. The relay
   flattens current Codex namespace tools for Ollama and restores their
   namespaces in the response.
4. The relay forwards signals and the Codex exit status, then removes the
   private catalog. A hard `SIGKILL` can leave a non-secret catalog artifact in
   the private runtime directory.

The runner deliberately exposes raw Codex arguments only after `--`. A local
model can invoke every Codex or MCP tool you make available, so keep the
read-only sandbox unless broader permissions are intentional. Do not expose an
unauthenticated Ollama daemon to untrusted networks.

For the full namespaced-MCP regression, see
[`scripts/collab-real-runtime-smoke.mjs`](../../scripts/collab-real-runtime-smoke.mjs).
The provider keys used here follow the official
[Codex configuration reference](https://developers.openai.com/codex/config-reference).
