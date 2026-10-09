# Notty

![Bubble BAI arriving at the QEMU dock in a bubble-wrap suit](imgs/awe0.png)

Notty is a local-first browser terminal workspace with MCP access, optional
terminal copilots, Docker-based development through Nosh, and experimental
network-evidence tooling through Nosh Guard.

> [!WARNING]
> Notty is pre-release software for trusted, single-user local use. Do not
> expose a checkout directly to the public Internet or untrusted users. The
> security and Guard subsystems include Labs work whose limitations are part of
> the interface, not hidden implementation details.

The package metadata currently identifies `1.0.0`; [RELEASE.md](RELEASE.md)
is the release authority and still marks the checkout **No-go** until its
applicable gates are complete.

Never run `npm`, `npx`, or `npm exec` on the host. Package installation, tests,
builds, audits, and packaging run inside Docker or an attached Nosh container.

## What Notty is

Notty brings several related pieces into one repository:

| Component | Current role |
| --- | --- |
| **Notty** | Next.js and Express terminal UI backed by `node-pty`, REST, WebSocket, and MCP transports. |
| **Nosh** | Project-scoped Docker launcher with profiles, generated local HTTP credentials, lifecycle commands, and optional app startup. |
| **Terminal Copilot** | Per-terminal Codex, Agy, or Ollama-assisted observation and command proposals. |
| **Collab** | Opt-in preview for coordinating multiple agents and their tmux terminals. |
| **Nosh Guard** | Linux/cgroup/eBPF Labs tooling for build and runtime evidence, audit, signed policy review, and guarded execution. |
| **Policy Review** | Standalone UI for inspecting a frozen semantic graph and exporting an explicit `NoshPolicyDecisionSet`. |

The shared terminal runtime lives in `lib/terminalManager.js`. Browser routes,
WebSocket handlers, and MCP tools all operate on that same set of terminal
sessions rather than maintaining separate terminal implementations.

## Major capabilities

- Create, split, resize, read, write, and stop terminal sessions from the
  browser.
- Expose the same terminal operations to MCP clients over Streamable HTTP,
  SSE, or stdio.
- Attach a visible copilot to a terminal, ask about selected terminal output,
  and keep explanation, insertion, approval, and autonomous control modes
  separate.
- Launch project-specific Nosh containers with optional Codex, Durdraw, Zig,
  Arduino, agent, and other profiles listed by `nosh --profile-list`.
- Enable Collab explicitly to supervise coordinated agent sessions and view
  their shared channel and terminals.
- Capture Docker build and guarded-runtime evidence, materialize review graphs,
  and preserve incomplete evidence without representing it as approval-ready.
- View and edit CP437/ANSI material with the vendored Durdraw integration.

## Containment and security

![The Great QEMU Containment Incident comic and containment architecture](imgs/awecomic.jpg)

*The QEMU containment incident is project lore. Current Nosh isolation is
Docker-based; Nosh Guard adds Linux cgroup/eBPF controls where the host meets
its explicit prerequisites.*

The practical boundaries are:

- The recommended Nosh command publishes Notty on `127.0.0.1`. Starting the
  server directly without a bind host can listen more broadly, so direct
  server launches require deliberate address and authentication configuration.
- OAuth Bearer authentication protects MCP in the default mode, while HTTP
  Basic authentication protects browser/admin routes and OAuth consent. A
  spawn OTP is a separate, single-use capability for terminal creation.
- Legacy Nosh is a convenient development container, not a boundary against a
  malicious Docker-authorized user or against trusted credentials deliberately
  mounted by a selected profile.
- Guard evidence and signed artifacts are fail-closed: incomplete coverage,
  unsupported target capabilities, digest drift, or an expired grant prevents
  activation.
- Policy Review records decisions; opening a graph does not approve or enforce
  anything.

Read [SECURITY.md](SECURITY.md) before deployment. Guard operators should also
read the [Guard design and operations guide](docs/nosh-guard.md) and the
[semantic policy review guide](docs/nosh-policy-review.md).

## Architecture and runtime modes

```text
Browser (Next.js + xterm) ── REST / WebSocket ─┐
                                               ├─ terminalManager ─ node-pty
MCP client ── HTTP / SSE / stdio ─ mcpTools ──┘

Nosh ─ Docker project container ─ Notty service
Nosh Guard ─ root host daemon + cgroup/eBPF evidence and enforcement backends
Policy Review ─ frozen graph + explicit DecisionSet export
```

`server.js` hosts the combined Next.js, REST, WebSocket, and MCP service. The
same MCP tool definitions are also available in standalone SSE and stdio
modes. From an attached Nosh shell, the corresponding package commands are:

```sh
npm run dev:ui
npm run start:sse
npm run start:stdio
```

Those commands are container-only. For the source layout and transport
relationships, see [Interface architecture](docs/interface-architecture.md).

## Quick start

The supported host workflow assumes Linux or WSL, Bash, Git, and a working
Docker Engine with BuildKit. Build Nosh and install the user-facing launcher
links:

```sh
cd /path/to/notty
./scripts/build-nosh.sh
./scripts/setup-nosh.sh
```

Use `nosh config` for browser-based repository profiles, copyable host setup
commands, and portable CI build-capture settings. See
[repository setup profiles](docs/nosh-repository-config.md).

`setup-nosh.sh` creates launch links under `~/.local/bin` by default but does
not edit shell startup files. Ensure that directory is on `PATH`, or invoke
`/path/to/notty/scripts/nosh.sh` directly.

The initialization wizard (`nosh init`, advanced step 2, or `nosh init --step setup`)
uses a host-side Python TUI by default, configures the current workspace, and stops after policy application; use
`nosh start` to start or attach afterward. See the [initialization guide](init.md).
Use `nosh init --classic` for the original guided prompts. The TUI uses an
isolated, hash-pinned Python virtual environment and never installs Node packages
on the host. Press `s` in the TUI to review and save portable setup selections
and immutable network/tool policy references as `.nosh/project.json`; host paths,
evidence, keys, and activation state remain local. The [initialization guide](init.md)
describes the manifest boundary.

Use `nosh uninstall` for a two-phase removal that cleans verified user setup
before separately offering Guard removal. Configuration and evidence are
preserved unless purge options are explicit. A Docker-only, kernel-qualified
Ubuntu 24.04 amd64 `.deb` build is documented in the
[Debian package guide](docs/nosh-debian-package.md).
It offers an optional Bubble Bai Codex pet installation after configuring launchers.
The default is No. **Bubble Bai has only been tested in Kitty terminal. Support
in other terminals is unverified.**

**Disclaimer:** Using Codex with Kitty, pets, and voice is an escape hatch
outside the coverage of the eBPF run profile. Do not treat host terminal, pet,
or voice integrations as contained or fully monitored by that profile.

To install it separately from this checkout:

```sh
sh bubble-bai-codex/install.sh
```

This installs as the current user, without sudo, into
`${CODEX_HOME:-$HOME/.codex}/pets/bubble-bai/`. See the
[Bubble Bai guide](bubble-bai-codex/README.md) for activation instructions.

Then launch Notty for a project. Publishing only to host loopback is
intentional:

```sh
cd /path/to/project
nosh recreate \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000
```

Nosh generates HTTP Basic credentials and one terminal-spawn OTP. Open
<http://127.0.0.1:3000/> and enter the Basic credentials printed by the
launcher. MCP clients use the OAuth authorization-code flow described below;
the Basic credential is entered only on the browser consent page.

### Authentication modes

MCP authentication and terminal-spawn authorization are intentionally
separate:

| Launcher mode | MCP and browser authentication | Terminal spawning |
| --- | --- | --- |
| default | OAuth Bearer for MCP; Basic for consent and UI | OTP required |
| `--noauth` | OAuth remains; Basic is disabled | OTP required |
| `--no-oauth` | Basic remains; OAuth is disabled | OTP required |
| `--no-otp-auth` | No Bearer, Basic, or other auth header | OTP required |
| `--no-otp` | Normal OAuth/Basic policy | OTP disabled |

All four disabling flags are restricted to loopback listeners and loopback
public origins. `--no-otp-auth` cannot be combined with `--no-otp` and is not
available in Guard mode. Guard keeps its mTLS gateway and starts each runner
with OTP enforcement enabled.

OAuth and consumed-OTP state is stored at
`${XDG_STATE_HOME:-$HOME/.local/state}/notty/auth/<workspace-id>/auth.sqlite3`
and mounted independently of container lifetime. `nosh auth reset`, run from
the same workspace, revokes that workspace's clients, grants, tokens, and
OTPs. After consuming a launcher OTP, `nosh auth otp` mints a fresh workspace
OTP and prints it once without enabling HTTP minting. Dashboard reads show OTP
status and timestamps, never reusable values.

The default reset manages legacy state under `XDG_STATE_HOME`. Guard keeps its
separate database below the root daemon state directory; reset it through the
root-only management socket with `sudo nosh auth reset --secure --workdir
/absolute/workspace`. Add `--dry-run` to print the delegated Guard command
without contacting the daemon or changing either state store.

### Connect Codex to MCP

For the default mode, register the Streamable HTTP endpoint on the host, then
run the browser login flow:

```sh
codex mcp add notty --url http://127.0.0.1:3000/mcp
codex mcp login notty
```

Approve the request in the browser using the launcher's Basic credential.
After Codex connects, provide the launcher's one-time OTP only as the `otp`
argument to a terminal-spawn tool.

For deliberate credentialless, loopback-only MCP access, launch with
`--no-otp-auth`, register the same `/mcp` URL, and connect without `codex mcp
login` or custom headers. Non-spawn tools are unauthenticated, but every spawn
still requires a fresh OTP. OAuth browser callbacks are initiated on the host;
do not try to perform the Codex login flow inside the container.

Plain `nosh` uses Docker. Select a backend before the command and its options:

```sh
nosh --docker
nosh --qemu
nosh --qemu status
```

`--qemu` uses the existing persistent VM with Docker inside it; its options
are listed by `nosh --qemu --help`. `--bwrap` is reserved and currently exits
with a not-implemented error. Conflicting backend selectors are rejected.
For persistent Codex work inside QEMU, see [persistent sessions](docs/nosh-qemu.md#persistent-codex-sessions).

Optional shell aliases (add them to your shell configuration yourself):

```sh
alias noshq='nosh --qemu'
alias noshb='nosh --bwrap'
alias noshd='nosh --docker'
```

Checkout launchers live in `scripts/`. Refresh an existing installed link with
`./scripts/setup-nosh.sh --replace-links`. The old `nosha`/`noshan`, `noshc`, and
`noshn` wrappers are replaced by `nosh attach`, `nosh --image noshc`, and
`nosh --network none`, respectively.

For ordinary Docker launches, a missing local image is built automatically when
`Dockerfile.<image-name>` exists in the project directory or this checkout
(project directory takes precedence). For example, `nosh --image nosh-zig`
builds `Dockerfile.nosh-zig`, including its local `nosh` base if needed. Image
tags share the same Dockerfile: `nosh-zig:dev` also uses `Dockerfile.nosh-zig`.
When an image and matching Dockerfile both exist, interactive launches offer
using the existing image (the default) or rebuilding it. Noninteractive launches
reuse existing images. Without a matching Dockerfile, Docker retains its
normal pull behavior. `--dry-run` never builds images. Guarded launches keep
their existing build and review workflow.

Use the same project directory for lifecycle commands so Nosh resolves the
same project-scoped container name:

```sh
nosh attach
nosh stop
nosh rm
```

To mount the Codex profile or enable the Collab preview:

```sh
nosh recreate -p codex --start-app --persist --publish 127.0.0.1:3000
nosh recreate --collab --start-app --persist --publish 127.0.0.1:3000
```

Profiles may expose selected host configuration or credentials to processes in
the legacy container. Use only profiles, agents, workspace code, and
dependencies you trust. The [copyable examples](EXAMPLES.md) cover Codex MCP
registration, Collab, tmux, offline containers, `vlock`, and guarded modes in
more detail.

## Audit Codex tool history

Generate local inspection and pending-review inventories from selected active
and archived Codex session history:

```sh
nosh tools init
# Explicit scope for a noninteractive audit:
nosh tools init --scope repo --no-prompt
# Optional input and output locations; the output directory must be new.
nosh tools init --scope all \
  --codex-home "$HOME/.codex" \
  --output-dir "$HOME/.local/state/nosh/codex-tool-audit/review-01"
```

`nosh tools init` asks for **this Git checkout**, **this directory and its
subdirectories**, or **all recorded history**. Every scope includes all recorded
dates. Repository scope starts at the checkout root, excludes other linked
worktrees, and is the default inside Git; elsewhere the default is directory
scope. Use `--workdir PATH` to select a different starting directory. With prompts
disabled or redirected input/output, `--scope repo|directory|all` is required.
Scope follows recorded session/turn working directories, not every file touched
by a command. Missing location metadata is excluded from scoped audits and makes
coverage incomplete. Moved/deleted checkout identities cannot be reconstructed.
The direct Python command remains available and defaults to all history.

This offline Python tool never executes recorded commands or changes active
Codex configuration. It requires no package installation. Its default output is
`${XDG_STATE_HOME:-$HOME/.local/state}/nosh/codex-tool-audit/<timestamp>-<pid>`.
Reports use private directory/file permissions and cannot be written inside the
checkout or Codex home.

When run in an interactive terminal, the audit finishes with a next-action menu:
review existing escape rules, browse pending or inspection groups, compare the
read-only and workspace-write profiles, open the tool-review UI, or finish.
Terminal groups are displayed 25 at a time. The UI saves proposed selections;
neither interface installs profiles, edits rules, or replays requests.
Start with the existing escape rules. Use `--no-prompt` to
skip the menu; redirected input or output also skips it automatically. An
incomplete snapshot still returns exit code `2` after review.

Choose **5 — Open review UI** for the same table and autosave workflow used by
network-profile review. Reopen a saved audit without scanning history again:

```sh
nosh tools review --review \
  "$HOME/.local/state/nosh/codex-tool-audit/REPORT_ID"
```

Run review on the host with Docker available. With no configured image, the
launcher finds a compatible local `nosh-policy-review:managed` image and remembers
its exact ID in the private `~/.config/nosh/policy-review-images.conf` used by
network review. If the image is missing or outdated, it offers to build the UI
in Docker and then opens this saved report. No rescan or manual image-ID export
is needed. Use `nosh tools review --review REPORT --build-ui` to allow that build
without a prompt. Builds may download dependencies; launching uses `--pull never`.
An explicit `NOSH_POLICY_REVIEW_UI_IMAGE=sha256:…` override is still supported and
is never automatically replaced.
See [tool-review setup](policy-review/README.md#tool-activity-review).

Classify each grouped form as **Expected**, **Investigate**, or **Unreviewed**.
Scanner suggestions start unconfirmed.
Progress saves under the report's private `review/` directory; review all forms,
enter a reviewer name, and acknowledge the proposal before finalizing. Download
or import JSON under **More options**. Imports must match the exact snapshot.
Incomplete audits can save drafts but cannot finalize a proposal. Saving never
changes runtime capabilities or creates sandbox-escape allow rules.

After saving the proposal, approve the container environment in the UI. Use
`nosh tools check`, then `nosh tools apply --policy-digest …` on the host.
`nosh init --advanced` includes tool review, check, apply, and status steps.
New containers automatically use the applied policy; `--tool-mode implementation`
requires explicit approval. The policy stays read-only inside Docker in both modes.
Codex remains an unmodified upstream executable. Activity classifications are informational;
Nosh enforces container filesystem capabilities, with network policy managed
separately. See [application, startup, rollback, and limits](docs/nosh-tool-policy.md).

- `allow.json`: reviewed local inspection forms, with frequencies and source
  line references. These are candidates for use **inside a sandbox**, not
  executable allow rules.
- `not-yet.json`: modifying, networked, and uncertain requests, grouped by
  tool/form and review reason. Unknown options, compound shell commands,
  embedded programs, JavaScript orchestration, and unreviewed MCP calls stay here.
- `rules-review.json`: accessible user, system, and current workspace ancestor
  rules that need review. It does not resolve project trust or remote managed rules.
- `summary.txt`: totals, classification limits, and any input problems.
- `planning.config.toml` and `implementation.config.toml`: proposed configuration
  profiles, **not installed automatically**.

Reports omit command arguments, prompts, credentials, and tool outputs. Source
references use conventional relative rollout filenames and 1-based line numbers;
other history filenames use `source-` plus the first 16 hex digits of SHA-256 of
the path relative to Codex home. Apart from `user/rules/default.rules`, rule
references use `rules-` plus the same hash length of their absolute path.
Each group includes up to three example references. Duplicate requests are
removed only when session ID, call ID, and request content match; conflicting
versions and requests without identities are retained. Counts reflect requests,
not proof that a command ran or succeeded. The scanner reads each file only up
to its opening size; changes during reading, oversized/malformed records, or
unreadable inputs are reported. Exit `0` means a complete scan, `2` means a
report was produced with input issues, and `1` means setup/output failed.

For Codex CLI 0.151.0, configuration profiles live beside `config.toml`. After
reviewing the generated files and inherited rules, install the selected profile
files there yourself and choose explicitly:

```sh
codex --profile planning        # Read-only local shell; no escalation prompts
codex --profile implementation  # Workspace writes; escalation requires review
```

Planning mode and permission selection are separate. Both examples keep shell
network access disabled. Implementation permits normal workspace/temp writes;
it does not make every pending command approved. A recorded `git diff`, `show`,
or `log` stays pending unless external diff and text conversion helpers are
disabled with `--no-ext-diff --no-textconv`. Interpreter and wrapper names alone
are never sufficient to classify their payloads as inspection.

Existing `prefix_rule(..., decision="allow")` entries may authorize execution
outside the sandbox. Review or remove conflicting entries before relying on the
planning boundary; do not convert this inventory into blanket executable-prefix
allows. Filesystem profiles also do not restrict remote MCP side effects. See
the official [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
and [command rules](https://learn.chatgpt.com/docs/agent-configuration/rules).
The offline audit does not test live sandbox enforcement; validate profiles on
a host that supports the required sandbox before relying on them.

## Build profiling and Policy Review

The project wrapper retains the normal Nosh image build and adds two evidence
workflows:

```sh
./scripts/build-nosh.sh
./scripts/build-nosh.sh profile
./scripts/build-nosh.sh net learn
```

`profile` captures build behavior and performance evidence. `net learn` forces
a clean build, learns its network requirements, persists the private and
portable artifacts, starts the managed Policy Review services, and prints a
Docker-bridge `172.*` review link. Use `--no-review` for CI or capture-only
runs:

```sh
./scripts/build-nosh.sh net learn --no-review
```

The one-click build learner opens **build evidence**. It does not create a
runtime candidate or Guard eBPF target context, and its DecisionSet cannot by
itself authorize `nosh net enforce`. Runtime enforcement requires a separate,
complete runtime profile plus the documented projection, review approval,
deployment grant, and activation flow. FQDN activation also remains blocked on
targets that report `tcpDns:false`.

The combined build-and-runtime capture entrypoint is:

```sh
./scripts/profile-build-and-review.sh --cache-mode cold
```

It requires the installed Guard host components and the exact reviewed tooling
and UI image prerequisites described in the Guard documentation. Exporting a
DecisionSet still does not skip projection, signatures, grant verification, or
activation.

Start with [Build profiling](docs/nosh-build-profiling.md), then use
[Policy Review](docs/nosh-policy-review.md) for the artifact and authority
lifecycle. The standalone UI under [`policy-review/`](policy-review/) remains
useful for reviewing incomplete evidence even when activation is not eligible.

## Alcatrazbox: the deeper systems layer

![Bubble BAI Alcatrazbox feature and lore overview](imgs/awecomic2.png)

*Alcatrazbox is the visual language for the containment work: policy walls,
blocked ghosts, verifier limits, and agents testing the edges. It is lore, not
a claim that every depicted backend or topology ships today.*

The deeper repository material is intentionally separated from the quick
start:

- [Nosh examples](EXAMPLES.md) — copyable local, agent, tmux, offline, and
  guarded workflows.
- [Nosh Guard](docs/nosh-guard.md) — privileged installation, evidence,
  health, runtime modes, and limitations.
- [Build profiling](docs/nosh-build-profiling.md) — BuildKit collectors,
  private/portable artifacts, and review handoff.
- [HTTP capture contract](docs/nosh-http-capture-contract.md) — optional
  managed HTTP observation and its trust boundary.
- [Policy Review](docs/nosh-policy-review.md) — frozen graphs, decisions,
  projection, signing, grants, and activation eligibility.
- [Gateway guide](docs/nosh-gateway.md) — external gateway targets and their
  separate authority model.
- [`examples/codex-ollama`](examples/codex-ollama/) — isolated Codex-to-Ollama
  compatibility relay example.

## Testing and maintenance

Run the release baseline from the host:

```sh
./scripts/release-audit.sh
```

Docker is mandatory. The audit performs dependency acquisition in constrained
networked containers, then runs deterministic tests, the production build,
advisory checks, and package inspection in its containerized release flow. It
writes `.release-audit/latest.md`; a zero exit status covers automated gates,
not the manual legal, provenance, image-scan, or live-provider checks listed in
the report.

The Docker-backed MCP terminal smoke is separate:

```sh
bash scripts/test.sh
```

After reviewing a dependency edit, regenerate the lockfile through its Docker
wrapper rather than a host package manager:

```sh
./scripts/regenerate-package-lock.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for validation and contribution rules.

## Disclaimer

Not my fault. Yes, I know—give me a week; I already thought of it. I still
need a few weeks before input. Everyone is your child, including you, so be
kind to all yourselves. ^.^

## Repository map

| Path | Purpose |
| --- | --- |
| [`server.js`](server.js) | Combined server and runtime-mode entrypoint. |
| [`pages/`](pages/) | Next.js pages and API routes. |
| [`components/`](components/) | Browser terminal and control UI. |
| [`lib/`](lib/) | Terminal, MCP, Copilot, Collab, Guard, and shared server logic. |
| [`config/`](config/) | Runtime, profile, schema, and Guard configuration. |
| [`scripts/`](scripts/) | Operational, audit, Guard, and smoke-test entrypoints. |
| [`policy-review/`](policy-review/) | Standalone managed review application. |
| [`ansi/`](ansi/) | ANSI/CP437 material and vendored Durdraw. |

## Project policy

- [License: 0BSD](LICENSE)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Release readiness authority](RELEASE.md)

## ANSI after dark

The ANSI/CP437 side of the project lives under [`ansi/`](ansi/).

Notty is available under the [0BSD license](LICENSE).

Development is the default runtime workload. See [build, dev, and run workloads](docs/nosh-workloads.md) for persistent agent homes, separate application policies, and reusable agent network baselines.
