# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- [Supported] Added a Docker-only release audit that performs repository,
  dependency, test, build, advisory, and package checks without running npm,
  npx, or Node.js on the host, and writes a Markdown report for every valid
  run.
- [Supported] Added copyable examples for running a source checkout, registering
  the MCP service with Codex on the host, attaching through the browser or tmux,
  and working in Docker's no-network mode.
- [Preview] Added examples for launching Collab profiles and observing their
  terminal sessions through Tilix and tmux.
- [Labs] Added guarded-network guidance for learning and auditing network
  behavior, asserting the runner/evidence boundary, and distinguishing current
  controls from the proposed clean-room-network design.
- [Labs] Added generic Docker build profiling with independent performance and
  clean-build network candidates, dedicated BuildKit builders, narrowly scoped
  host eBPF collection, and redacted portable CI artifacts.
- [Labs] Added a combined build-and-runtime profiling script plus a cleanup-safe
  timed `nosh net learn` mode for displaying build evidence, a three-minute
  egress-only runtime policy, and the exact human review/application commands.
- [Supported] Added a checksummed, target-host Guard installation bundle with a
  pinned bundled Node runtime, complete local CLI/daemon module closure,
  CO-RE loaders, manifest-gated systemd startup, scoped CI sudoers support,
  verification, and state-preserving uninstall.
- [Supported] Added the root 0BSD license and public-release policies for
  third-party notices, security reporting, contributions, and changelog
  maintenance.
- [Supported] Added opt-in `vlock` support for individual Nosh terminals with
  interactive in-container password setup kept separate from the lockdown
  view, HTTP credentials, MCP, and terminal WebSocket policy.
- [Supported] Added a Docker-only lockfile regeneration command that receives
  only `package.json`, disables lifecycle scripts and non-registry dependency
  sources, rejects production advisories, structurally revalidates the
  candidate in a second no-network container, and atomically replaces
  `package-lock.json` without host npm, npx, or Node.js.
- [Supported] Added pull-request, branch, tag, and manual CI around the
  Docker-only release audit, with an untagged pre-release check that accepts
  only the missing candidate tag as an outstanding automated gate. Checkout is
  action-free and uses host Git without host Node.js or package-manager work.

### Changed

- [Supported] Moved the pinned Ollama CLI and runtime libraries into an
  explicit `ollama` Docker target. The default `local` image and the existing
  `base`, `agent`, `hardware`, `cdev`, and `full` targets no longer bundle the
  large Ollama distribution or its decompression tool. The ordinary build
  launcher forces BuildKit so those targets also skip the disconnected Ollama
  artifact stage when a caller has disabled BuildKit in the environment.
- [Supported] Changed managed Ollama agents to query the configured daemon for
  an already-installed model and invoke Codex with an isolated Responses
  provider through a per-launch loopback relay. The relay preserves current
  Codex namespaced MCP tools against Ollama 0.31.2. Managed launches no longer
  depend on the Ollama CLI, rewrite shared Codex profiles, or implicitly pull
  missing models.
- [Supported] Added a standalone `examples/codex-ollama` runner that exercises
  the same provider preflight and compatibility relay with safe read-only
  defaults and no duplicated Ollama client implementation.
- [Labs] Scoped Guard runner task exhaustion to Docker's per-container cgroup
  PID limit instead of also setting `RLIMIT_NPROC`, whose real-UID-wide Linux
  accounting could prevent `docker-init` from executing for a busy host user.
- [Labs] Added a managed-egress image ABI gate before gateway/network mutation
  and made legacy or stale policy acknowledgements fail immediately with
  field-level diagnostics instead of a generic ten-second timeout.

### Security

- [Supported] Added release gates for clean repository state, stable audit
  inputs, and offline package inventories that reject known runtime,
  credential, log, cache, and agent-state paths.
- [Supported] Updated the MCP SDK and Next.js constraints and pinned reviewed
  Hono, Fast URI, PostCSS, and Sharp overrides above their current advisory
  fix floors; the release audit remains the authority for the resolved graph.
- [Supported] Raised the transitive `hono` floor to 4.12.34 for
  GHSA-8j4g-w8fx-2239 (CVE-2026-69207), the CORS preflight ReDoS disclosed on
  2026-08-03.
- [Supported] Disabled npm publication with `private: true`, made test
  fixture execution explicit only in the offline audit phase, and removed the
  out-of-project dependency symlink rejected by Next.js Turbopack.

### Removed

- [Supported] Removed current private artwork, generated agent/Collab state,
  logs, cache data, and the local OAuth bootstrap helper from release tracking
  and package/container contexts while retaining ignored local copies where
  provenance or operator recovery still requires them.
