# Build, dev, and run workloads

Plain `nosh` and runtime learning default to **dev**. Development containers
reuse existing Codex, Claude, and Gemini state from the invoking host user.
Learning and enforcement use the same recorded home mounts, image, workspace,
Collab selection, and app-start choice. Authentication refreshes and sessions
persist on the host after a container exits.

| Workload | Command | Default behavior |
| --- | --- | --- |
| Build | `nosh build profile` or `nosh build net learn` | Profile image creation; no agent-home mounts |
| Dev | `nosh` or `nosh net learn --workload dev` | Interactive development shell, available agent homes; guarded development and learning keep the app stopped |
| Run | `nosh --workload run` or `nosh net learn --workload run` | Application runtime, app started, no agent-home mounts or Collab |

Ordinary Docker launches start Notty automatically outside this checkout. In
the Notty checkout, interactive launches ask whether to start the bundled
service (default: No); dry runs and noninteractive launches leave it stopped.
Attaching to an existing container preserves its startup choice. Use
`nosh recreate --start-app` to replace a shell-only container with one running
the service.

`--start-app` and `--no-start-app` override app startup. The bundled application
entrypoint remains `/app`; other repositories need a Guard-compatible image
with their application and development tools already installed. Workload
selection does not install agent CLIs into an arbitrary application image.

## Agent homes

```bash
nosh init --step learn --workload dev
nosh --workdir /absolute/other-repository
nosh --agents codex
nosh --agents none
nosh init --step learn --agents codex --codex-home /absolute/custom-codex
```

`--agents auto` is the default: use existing `~/.codex`, `~/.claude`, and
`~/.gemini` directories. Existing `~/.claude.json` is included with Claude.
Explicitly selecting an agent whose directory is missing fails with a path
and initialization hint. `--agents none` disables these default mounts.
Existing mount presets remain available through `--profile`; workload
selection is a separate option.

`CODEX_HOME` or `--codex-home` selects a custom Codex source. The launcher and
wizard pass this path explicitly through sudo. When invoking Guard directly,
use `--codex-home` because sudo may discard environment variables:

```bash
sudo /opt/notty/bin/nosh-guard net learn --workload dev \
  --workdir "$PWD" --image nosh --agents codex \
  --codex-home "$HOME/.codex" --review-output
```

Guard resolves the invoking user from numeric sudo identity and mounts agent
state under `/home/nosh-guard`, with `CODEX_HOME` set accordingly. State is
read/write, including authentication and configuration. Guard validates
ownership, canonical paths, directory identity, and the live mounts before
releasing the runner. World-writable state and symlinked source paths
are rejected. Credential contents are neither hashed nor exported as policy
evidence. Replacing a home directory or changing the selected homes requires
new learning; ordinary credential-file refresh inside a mounted directory
does not.

## Separate workspace policies

```bash
sudo nosh net learn --workload dev --no-start-app
nosh net review --workload dev
# Finish review and use the session/digest shown by the review UI:
nosh net apply --workload dev --review /absolute/session \
  --decision-digest sha256:YOUR_DECISION_DIGEST
nosh net status --workload dev
nosh --workload dev
```

Repeat with `--workload run` for the application policy. Each physical workspace
has independent dev/run candidates, mirrors, and applied activation slots.
Applying one does not replace another workspace's policy. Basename-derived
ordinary container names include the workload; Guard names also include the
workspace hash. Existing containers must match the requested workload.

After updating the installed Guard host bundle and launcher, learn fresh dev
and run profiles. Reprofile any existing experimental workloads.
Existing build commands are unchanged.

For lower-level activation diagnostics, supply both selectors:

```bash
sudo /opt/notty/bin/nosh-guard ebpf status --workload dev --workdir "$PWD" --json
```

## Reusable agent network baselines

A baseline is a versioned **review input** for one agent. Create it from that
agent's learned connection inventory using this format (replace example
values with the actual tool version, exact image digest, and observed rules):

```json
{
  "schemaVersion": 1,
  "agent": "codex",
  "revision": "codex-v1",
  "imageDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "toolVersion": "1.2.3",
  "rules": [
    { "destination": "api.example.com", "protocol": "tcp", "ports": [443] }
  ]
}
```

Pin the file bytes when selecting it. Repeat `--agent-baseline` for Claude
and Gemini; select at most one revision per agent:

```bash
baseline="$HOME/.config/nosh/codex-v1.json"
digest=$(sha256sum "$baseline" | cut -d ' ' -f 1)
nosh init --step learn --workload dev --agents codex \
  --agent-baseline "$baseline@sha256:$digest"
```

The file must be caller-owned, at most 1 MiB, and not group/world writable.
Its exact image digest must match the learned container, and its agent must
be selected and available. Rules support destination, protocol, ports, and
optional ICMP type/code. Arbitrary observation payloads are not accepted.

Learning snapshots the baseline, merges duplicate rules with workspace
observations, and carries its agent, revision, digest, and tool version into
review evidence. The image digest pins the installed tool; a tool-version
string alone is not an executable attestation. No baseline is enforced until
the composed workspace policy is reviewed, signed, and activated. Changing
the source file does not change an existing candidate or applied policy.

The composed permissions apply to the entire dev container. Build and run
do not import agent baselines. Existing projection constraints still apply:
a domain-only baseline does not invent the literal address evidence required
by the eBPF backend. Exercise those connections during learning and inspect
any unresolved requirements in review.

## Validation

Use Docker for all tests and builds. `./scripts/release-audit.sh` is the host baseline;
inside a Nosh container, `npm test` includes `tests/nosh-workload.test.cjs`.
For a live smoke test, learn dev in Notty and another checkout, exercise each
authenticated agent, exit, review/apply, and relaunch. Confirm sessions survive
recreation and that `--workload run` exposes no host agent homes. Live provider
authentication and eBPF admission require the corresponding host services.
