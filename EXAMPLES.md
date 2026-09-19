# Nosh examples

These examples start with the smallest local-development setup and then build
up to Collab and Nosh Guard. They assume Linux or WSL, Docker, and a local
checkout of Notty. See the [main README](README.md) for prerequisites and the
full launcher reference.

Never run `npm`, `npx`, or `npm exec` on the host. Nosh image builds, lockfile
regeneration, and the release audit execute package-manager operations inside
Docker only.

## Hands-on usability pass

Run the examples in order from a disposable project directory and record the
host OS, Docker version, Notty commit, image ID, elapsed setup time, and any
step that required knowledge not written here. An example counts as usable
only when its success check and cleanup both work by copying the documented
commands; a process merely starting is not enough.

| Example | Observable acceptance check |
| --- | --- |
| Release audit | The report identifies the exact commit and distinguishes automated evidence from unevaluated manual gates. |
| Lockfile regeneration | The networked candidate has no known production advisories in the queried service, offline validation passes, and only the reviewed lockfile is replaced. |
| Source directory with Codex | The browser loads, Codex `/mcp` shows Notty connected, and a live `list_terminals` call succeeds. |
| Collab browser profile | Human and agent coordination each launch the intended roster, and every managed agent has one distinct tmux session. |
| Tilix and tmux | A viewer can detach and reattach without stopping the agent, and separate panes can watch separate sessions. |
| `vlock` | Only the selected PTY locks; a peer pane and the service remain usable. |
| Docker `--network none` | An external DNS lookup or HTTPS request fails while local offline work still succeeds. |
| Guard learning | A deliberately stopped run produces complete, run-bound network evidence for the exercised traffic. |
| Guard audit | The manifest binds the exact candidate hash and reports would-deny results without claiming enforcement. |
| Guard evidence boundary | The runner cannot see the Guard state tree or control socket, while the host retains root-owned evidence. |

The Nosh lifecycle examples intentionally omit `--name`. Nosh derives
`nosh-<sanitized-workdir-basename>` from the resolved working directory; when
`--workdir` is omitted, that is the basename of `$PWD`. Verify that `recreate`,
`attach`, `stop`, `rm`, and `set-login-password` all resolve that same name
when run from the same directory.

For every container example, finish with the documented `stop` and `rm`
lifecycle commands and confirm no unexpected container, network, published
port, credential file, or project mutation remains.

## Audit release readiness from the host

Run the audit host entrypoint from the Notty checkout:

```sh
cd /path/to/notty
./release-audit.sh
```

Docker is mandatory; the audit stops instead of falling back to host npm. The
host wrapper also needs Git, Python 3 for strict JSON metadata parsing, and
standard GNU tools. It uses manifest-only networked containers for dependency
acquisition and the advisory service, then runs native rebuilds, tests, the
production build, and package creation in a separate `--network none`
container. A final offline, no-script inventory checks an ephemeral copy of the
complete checkout for package leaks.

The default Markdown report is `.release-audit/latest.md`. It is written even
when a valid audit stops early, such as when Docker is unavailable, and records
an `INCOMPLETE` or `INTERRUPTED` outcome instead of implying that unrun gates
passed. To retain a named report outside the ignored local report directory:

```sh
./release-audit.sh --report /path/to/notty-audit.md
```

Custom reports must be outside the checkout or under `.release-audit/` so they
cannot accidentally enter a source archive or package. Automated passes appear
as checked boxes only inside the generated report. Failed, skipped, warned, and
unrun gates stay unchecked. Manual gates also remain unchecked, and the audit
never edits `RELEASE.md`. Release-tag evidence passes only when the captured
`package.json` version matches the candidate in the captured `RELEASE.md` and
that commit has the same exact tag, with an optional `v` prefix.

## Regenerate the dependency lockfile safely

After reviewing dependency constraints in `package.json`, run:

```sh
cd /path/to/notty
./regenerate-package-lock.sh
```

This is a maintenance command, not a release certification. It sends only
`package.json` to a locked-down networked container, generates a completely new
lock with scripts and non-registry dependency sources disabled, requires the
queried advisory service to report no known production advisories, and
validates the candidate again in a no-network container before replacing
`package-lock.json` atomically. It never supplies
the old lockfile or `node_modules` and never runs npm, npx, or Node.js on the
host.

If the old lock already has partial generated changes that you have reviewed
and intend to replace, acknowledge that explicitly:

```sh
./regenerate-package-lock.sh --replace-dirty-lock
```

Review `git diff -- package.json package-lock.json`, then commit all reviewed
dependency and generator changes. Run `./release-audit.sh` only after the
worktree is clean. Leave `v1.0.0` uncreated until its absence is the sole
automated audit failure; tag that exact commit and rerun the audit.

## Run a source directory with Codex

Build Nosh once from the Notty checkout, then configure the user launchers; no
host package-manager installation is needed:

```sh
cd /path/to/notty
./build-nosh.sh
./setup-nosh.sh
```

The setup command creates the `nosh` and development `nosh-guard` links. Use
`--bin-dir DIR` to choose another command directory, or invoke
`/path/to/notty/nosh.sh` directly.

Start the project-scoped service in its default authentication mode:

```sh
cd /path/to/project
nosh recreate \
  -p codex \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000
```

Then register and authenticate from a **host** shell:

```sh
codex mcp add notty --url http://127.0.0.1:3000/mcp
codex mcp get notty
codex mcp login notty
```

The login command opens the browser authorization-code flow. Enter the Basic
credential printed by Nosh, review the requested `mcp:tools` scope and exact
`/mcp` resource, and choose Allow or Deny. Codex performs DCR and PKCE and
stores its refreshable client authorization on the host. Do not run `codex mcp
login` inside the container; this project does not support container-initiated
browser callbacks.

Start Codex on the host and use `/mcp` to confirm that `notty` connected. Nosh
also prints one spawn OTP. Submit it only as the MCP tool's `otp` argument when
creating a terminal. It is consumed once even if PTY creation subsequently
fails; never put it in an Authorization header, URL, cookie, config file,
browser storage, prompt file, or shell history.

For credentialless MCP on a trusted workstation, use the explicit OTP-only
mode instead:

```sh
cd /path/to/project
nosh recreate \
  -p codex \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000 \
  --no-otp-auth

codex mcp add notty --url http://127.0.0.1:3000/mcp
codex mcp get notty
```

Do not run `codex mcp login` and do not configure an Authorization header in
this mode. Listing and other non-spawn tools are unauthenticated; spawning is
still fail-closed and requires the launcher OTP. `--no-otp-auth` is accepted
only with loopback listener/public-origin configuration, cannot be combined
with `--no-otp`, disables HTTP OTP minting, and is rejected in Guard mode.

Mint another OTP locally after the launcher's value has been consumed:

```sh
cd /path/to/project
nosh auth otp
```

The command stores only the hash and lifecycle record in persistent state and
shows the new plaintext once.

The default and OTP-only workflows both keep authentication/OTP state outside
the container at
`${XDG_STATE_HOME:-$HOME/.local/state}/notty/auth/<workspace-id>`. Recreating a
container does not resurrect a consumed OTP. To invalidate every registered
client, grant, token, and OTP for the current workspace, run:

```sh
cd /path/to/project
nosh auth reset
```

Guard runners use the daemon's separate root-owned state tree. Reset the
derived workspace database through its management socket (or add `--dry-run`
to preview the delegation):

```sh
sudo ./nosh.sh auth reset --secure --workdir /absolute/path/to/project
```

Run lifecycle commands from the same project directory so Nosh resolves the
same directory-derived container name:

```sh
nosh attach
nosh stop
nosh rm
```

## Update an agent or its host configuration

Treat the running container as an instance, not as the source of agent
updates:

1. Change MCP registrations and agent authentication on the host.
2. Change reviewed agent version pins or image source in the Notty checkout.
3. Rebuild the image with `./build-nosh.sh`.
4. Return to the source directory and run `nosh recreate` with the desired
   profiles and flags.

Installing or upgrading a global agent CLI inside a running container is
ephemeral, bypasses the reviewed image definition, and disappears on
recreation. Recreate the container after host configuration changes as well,
so its mounts and launch-time settings are unambiguous.

## Launch a Collab profile in the browser

Start a fresh development container with Collab enabled:

```sh
cd /path/to/project
nosh recreate \
  --collab \
  -p agents \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000 \
  --noauth
```

This legacy `agents` profile projects host Codex, Gemini/Agy, and Claude state
into one container, and all Collab agents currently share one Unix identity.
Agents and workspace code or dependencies can read or use every mounted
provider credential available to that identity. Use this workflow only with
mutually trusted agents and trusted workspace contents; current Collab does
not provide per-agent credential isolation.

Open <http://127.0.0.1:3000/collab>, select a built-in profile such as **Pair
Review**, choose a coordinator mode, enter the task, and select **Launch
profile**.

- **Human** coordination omits coordinator-capable agent roles and leaves
  coordination to the operator.
- **Agent** coordination launches exactly one coordinator-capable role and
  gives that agent the task to coordinate.

For a browser-managed session, Collab gives each managed Codex process a
session-specific `notty_collab_session` MCP URL through launch arguments. It
does not require, and should not create, a persistent
`codex mcp add collab` entry. The global `collab` registration documented in
the [Collab operations guide](README.md#collab-operations) is for standalone
or manually launched clients that connect directly to a Collab daemon.

## Watch Collab agents with Tilix and tmux

The HTTP view is optional. Collab agents run in detached tmux sessions inside
the Nosh container, so a normal terminal can attach to them directly.

Open a new Tilix pane or window, enter the same source directory, and attach
to the persistent container:

```sh
cd /path/to/project
nosh attach
```

Inside the container, list the exact session names and attach to one:

```sh
tmux list-sessions -F '#S'
tmux -u attach-session -t SESSION_NAME
```

Use `Ctrl-b d` to detach without stopping the agent. To watch several agents,
open one Tilix pane per agent, run `nosh attach` in each, and attach each pane
to a different tmux session.

A local Tilix profile can set its custom command to:

```sh
bash -lc 'cd /path/to/project && exec /path/to/notty/nosh.sh attach'
```

Keep that profile local: its project path, profile UUID, pane layout, and
window geometry are machine-specific and are not portable repository data.

## Lock one attached terminal with vlock

For an existing persistent legacy Nosh container, set the container account's
Unix password from the host with an interactive prompt:

```sh
cd /path/to/project
nosh set-login-password
```

The password is intended here for `vlock`, but it is the account's general
Unix password and another PAM consumer added to the image could accept it.
It is not Notty Basic Auth, is never passed as a launcher argument or
environment value, and disappears when the container is recreated. Nosh Guard
runners reject this command.

Attach to the terminal you want to pause and run:

```sh
vlock
```

This locks only that PTY. It does not lock peer tmux panes, browser sessions,
Notty APIs, agents, the container, or the host.

## Work offline with Docker's no-network mode

For an existing image and source tree that need no network:

```sh
cd /path/to/project
nosh recreate \
  --network none \
  --no-start-app \
  --persist
```

This is the current simple connectivity-isolation option. It is useful for
local compilers, tests, and inspection, but has important limits:

- hosted agents, package downloads, and host Ollama services are unreachable;
- `--no-start-app` leaves no Notty browser or MCP service to connect to;
- Docker's `none` network does not record attempted DNS lookups or
  connections; and
- legacy Nosh mounts are still legacy credential/filesystem behavior, so
  network isolation is not per-agent credential isolation.

From the shell opened inside that container, make the denial observable without
installing anything:

```sh
git status --short >/dev/null

if timeout 5 getent ahosts registry.npmjs.org >/dev/null 2>&1
then
  echo 'unexpected external DNS resolution' >&2
  exit 1
fi

if curl --fail --silent --show-error --max-time 5 \
  https://registry.npmjs.org/ >/dev/null 2>&1
then
  echo 'unexpected external network access' >&2
  exit 1
fi

echo 'offline local work succeeded and external HTTPS was denied'
```

Exit the shell, then clean up from the same host project directory with
`nosh stop` and `nosh rm`.

Use this mode when denial alone is enough. The proposed deny-and-observe
clean-room mode is described under [Nice-to-have hardening](#nice-to-have-hardening).

The current network modes make different promises:

| Mode | Connectivity and evidence contract |
| --- | --- |
| Legacy Docker networking | Ordinary Docker connectivity; no Guard network-evidence claim. |
| `--network none` | External connectivity is denied, but attempted DNS and connections are not recorded. |
| Guard `learn` | Egress is recorded and normally allowed, while invariant private-network and direct-DNS denies remain active. |
| Guard `audit` | Candidate would-deny decisions are recorded, but the candidate is not enforced; invariant denies remain active. |
| Guard `enforce` | The standalone manager currently rejects admission because complete ingress enforcement is unavailable. It must not be described as allowlist confinement. |

`NOTTY_LOCKDOWN=true` is an HTTP/UI restriction, not network isolation or an
egress policy. Do not use the lockdown page as evidence for any row above.

## Profile network behavior with Nosh Guard

Nosh Guard is a root-owned prototype with substantial host prerequisites.
Read the [operations and profile lifecycle guide](docs/nosh-guard.md) before
installing it. Run the non-mutating preflight first:

```sh
cd /path/to/notty
bash scripts/nosh-guard-doctor.sh --mode learn
```

On an unprovisioned host, build the reviewed Guard archive with Docker; do not
restore the old host `npm install --global` workaround:

```sh
./scripts/build-nosh-guard-host-bundle.sh
```

The wrapper needs Docker and readable host BTF, but no host Node.js, npm, or
compiler. It builds the exact digest-pinned Node.js `v24.18.0` Bookworm image,
then runs the packager offline and non-root with read-only source and BTF
mounts, executable scratch tmpfs, and only the output directory writable.
Review and checksum the result before running only its installer with `sudo`,
as shown in the guide's
[sensor installation](docs/nosh-guard.md#installing-the-sensor-assets).
The Bookworm-built loaders retain userspace shared-library requirements, so
run the installer's `--deep-verify` check on the target host before enabling
the service. The remaining commands also require the root configuration,
runner and gateway images, Tetragon, and systemd unit described there.

On an already provisioned host, enable the daemon and require a passing
learn-mode doctor:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now nosh-guardd.service
sudo nosh-guard doctor --mode learn
```

Do not continue unless the last command exits successfully. A running daemon
alone does not prove that Docker, Tetragon, Inspektor Gadget, nftables,
AppArmor, the loader, or either image is ready.

From the project, save its absolute path, then return to the Notty checkout:

```sh
cd /path/to/project
PROJECT_DIR="$(pwd -P)"
cd /path/to/notty
```

Start a representative learning run:

```sh
sudo ./nosh.sh start \
  --security-mode learn \
  --image nosh \
  --workdir "$PROJECT_DIR" \
  --persist
```

Exercise startup, builds, tests, package-manager behavior, expected failures,
idle periods, and clean shutdown. Learning records and permits network traffic
except invariant host/private-network denies; it is profiling, not
default-deny enforcement. Stop deliberately so collectors can flush and the
manifest can be finalized:

```sh
sudo ./nosh.sh stop \
  --security-mode learn \
  --image nosh \
  --workdir "$PROJECT_DIR"

sudo ./bin/nosh-guard runs

sudo ./nosh.sh rm \
  --security-mode learn \
  --image nosh \
  --workdir "$PROJECT_DIR"
```

Copy the stopped run's `evidenceManifest` path from `nosh-guard runs`. Compile
that evidence into a new, unapproved candidate directory only after reviewing
the intended Tetragon hooks against the target kernel. Copy the example rules
to a root-controlled review location, review and modify them there, and replace
`/path/to/reviewed-tetragon-rules.json` below. Supplying
`--reviewed-tetragon-enforcement` is an operator attestation that this review
already happened; the compiler does not perform it.

```sh
sudo ./bin/nosh-guard profile compile \
  --evidence /var/lib/nosh-guard/evidence/LEARN_RUN_ID/evidence-manifest.json \
  --name example-v1 \
  --tetragon-rules /path/to/reviewed-tetragon-rules.json \
  --reviewed-tetragon-enforcement \
  --output /var/lib/nosh-guard/profiles/example-v1-audit-input
```

Replace `LEARN_RUN_ID` with the recorded run ID.
Here `profile compile --name example-v1` names the profile; it is not a
container-name override.

Run the exact, unchanged candidate in audit mode:

```sh
sudo ./nosh.sh start \
  --security-mode audit \
  --security-profile-dir \
    /var/lib/nosh-guard/profiles/example-v1-audit-input \
  --image nosh \
  --workdir "$PROJECT_DIR" \
  --persist

sudo ./nosh.sh stop \
  --security-mode audit \
  --image nosh \
  --workdir "$PROJECT_DIR"

sudo ./bin/nosh-guard runs

sudo ./nosh.sh rm \
  --security-mode audit \
  --image nosh \
  --workdir "$PROJECT_DIR"
```

Audit snapshots the candidate hashes and records egress would-deny decisions,
but it does not enforce the candidate. The following check makes the intended
network assertion explicit. Replace `AUDIT_RUN_ID`, then run it on the host:

```sh
AUDIT_MANIFEST=/var/lib/nosh-guard/evidence/AUDIT_RUN_ID/evidence-manifest.json

sudo python3 - "$AUDIT_MANIFEST" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

evaluation = manifest.get("auditEvaluation") or {}
network = (evaluation.get("backends") or {}).get("network") or {}
network_policy_hash = (evaluation.get("candidateArtifacts") or {}).get(
    "network-policy.yaml"
)
passed = (
    manifest.get("complete") is True
    and isinstance(network_policy_hash, str)
    and network.get("complete") is True
    and network.get("wouldDenyCount") == 0
)

print(json.dumps({
    "evidenceComplete": manifest.get("complete"),
    "networkPolicyHash": network_policy_hash,
    "network": network,
}, indent=2))
raise SystemExit(0 if passed else 1)
PY
```

This assertion is expected to exit nonzero in the current implementation:
the managed gateway observes egress, but the artifact's ingress policy and
several non-network backends do not have audit evaluators. Consequently the
audit is non-promotable even when `wouldDenyCount` is zero. The shipped
standalone `enforce` mode is also intentionally unavailable and fails with
`GUARD_STANDALONE_INGRESS_UNAVAILABLE`. Follow the full
[learn/compile/audit workflow](docs/nosh-guard.md#learn-compile-and-audit-workflow)
for the compiler and approval gates; do not treat this illustrative check as
a substitute for them.

To test the egress profiler itself, use two independent audit runs against the
same candidate. In the positive run, exercise only the intended destinations
and require `network.evaluator` to equal
`managed-gateway-egress-only` with `wouldDenyCount` equal to `0`. In the
negative-control run, attempt one known unlisted public destination and require
`wouldDenyCount` to be greater than `0`. Keep the runs separate because the
counters are cumulative and background traffic can affect them. The unlisted
request is still allowed in audit mode, and `network.complete` remains `false`
because ingress is not evaluated; this proves the shadow decision signal, not
network confinement.

The underlying
[L3/L4 evidence sensor](bpf/nosh_l4/README.md) is observe-only. Its
`verdict=allow` records what the sensor did, not whether a connection
succeeded, and the sensor cannot enforce a network policy by itself.

## Assert the audit-evidence boundary

During a guarded run, execute this sanity check inside the runner shell:

```sh
if grep -Eq '/var/lib/nosh-guard|/run/nosh-guardd\.sock' /proc/self/mountinfo
then
  echo 'unexpected Guard state or socket mount' >&2
  exit 1
fi

test ! -e /var/lib/nosh-guard
test ! -S /run/nosh-guardd.sock
echo 'Guard evidence and control socket are outside the runner'
```

The supported guarded runner receives the writable project workspace, not the
host evidence tree or Guard control socket. Therefore code in the container
has no read or write path to `/var/lib/nosh-guard/evidence`; the useful
assertion from inside the container is isolation, not a filesystem
append-only flag.

After stopping the run, inspect ownership from the host:

```sh
sudo stat -c '%U:%G %a %n' \
  /var/lib/nosh-guard \
  /var/lib/nosh-guard/evidence \
  /var/lib/nosh-guard/evidence/RUN_ID

sudo find /var/lib/nosh-guard/evidence/RUN_ID \
  -maxdepth 1 -type f -printf '%u:%g %m %p\n'
```

Replace `RUN_ID` with the recorded run ID. Guard evidence directories are
host-owned mode `0700` and evidence files are mode `0600`. Shared managed-DNS
and gateway logs are opened append-only, and truncation or inode replacement
during a run makes the evidence incomplete.

This is not WORM storage or protection from the host administrator. A host
root process can replace state, and the current unkeyed hashes detect changes
but do not authenticate who created the original evidence. Preserve the
root-owned state tree and use external signed provenance when evidence crosses
an administrative boundary.

## Nice-to-have hardening

These are design targets, not current command-line options:

- **One Unix identity per agent.** Give every agent its own UID, home,
  credential capability, and non-shared authentication files so peers cannot
  read or overwrite one another's provider tokens. Add an explicit
  observation broker for tmux because separate users cannot safely share a
  tmux socket. Avoid passing provider credentials through a common
  environment or writable project directory.
- **`clean-room-network`.** Start with all ingress and egress denied while
  host-side sensors record attempted DNS names, literal-IP connects,
  protocols, ports, process attribution, loss counters, and timestamps.
  Retain evidence across long idle windows so a package that phones home six
  hours after launch is visible. The recorder must not resolve/forward DNS,
  auto-allow observed traffic, or silently turn learned destinations into
  policy.
- **Stronger tamper evidence.** Add signed or keyed manifests, hash-chained
  append records, periodic external checkpoints, and immutable or remote
  retention when the threat model includes a privileged host writer.

For implementation details and current limitations, continue with
[Nosh Guard operations](docs/nosh-guard.md), the
[L3/L4 sensor contract](bpf/nosh_l4/README.md), and the
[agent/tmux notes](agents/README.md).
