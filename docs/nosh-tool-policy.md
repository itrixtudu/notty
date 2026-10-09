# Tool activity review and container environment policy

Codex remains an external, upstream executable. Nosh reads historical requests
as evidence, records human activity classifications, and separately enforces an
approved **container filesystem policy**. It does not patch Codex or install
executable allow rules.

## Review and apply

From `nosh init`, use **More… → Manage Policies → Dev Tools** for the same
Docker-backed React editor. Select a discovered workspace-scoped report or load
another report directory. Initialize history explicitly when no report exists.
After saving in the browser, Verify status, Validate, and Apply from the hub;
the wizard confirms the exact digest and checks installed status. Opening the
editor is not approval, and existing containers are not recreated.

1. Run `nosh tools init`. Choose this Git checkout, this directory and its
   subdirectories, or all recorded history. All choices include all recorded
   dates; checkout scope excludes other worktrees. The next-action menu opens
   the review UI. For batch use, specify `--scope repo|directory|all --no-prompt`.
   Historical requests are never executed.
2. Reopen on the host with `nosh tools review --review /absolute/report/path`.
   Docker is required. The launcher remembers a compatible local managed UI
   image, or offers to build a missing/outdated image in Docker before opening
   the saved report. Add `--build-ui` to allow this build without a prompt;
   no rescan or manual image-ID export is needed.
   Classify grouped tool activity as **Expected**, **Investigate**, or
   **Unreviewed**, complete the reviewer name and acknowledgement,
   then **Save reviewed proposal**.
3. In **Enforced capabilities**, enter the canonical host workspace
   path. Read-only is the default. Explicitly allow implementation mode if
   workspace writes are required. Acknowledge the limitations and **Save
   environment policy**. Saving does not activate anything.
4. Check and apply the exact saved digest:

   ```sh
   nosh tools check --review "$REPORT" --workdir "$WORKSPACE"
   nosh tools apply --review "$REPORT" --workdir "$WORKSPACE" \
     --policy-digest sha256:THE_DIGEST_PRINTED_BY_CHECK
   nosh tools status --workdir "$WORKSPACE"
   ```

Apply requires the updated, installed Nosh Guard host bundle and invokes its
root-owned authority through sudo. It never elevates the mutable checkout.
Use `--guard-prefix /your/prefix` if Guard is installed outside `/opt/notty`.
The digest binds the exact environment file to its audit snapshot, completed
proposal, and workspace. Root-owned revisions and the atomic active pointer live
in `/var/lib/nosh-tool-policies`, outside the workspace.

The existing wizard is **`nosh init`**, not `start.sh`. Its advanced menu adds
9 Review tools, 10 Check tool policy, 11 Apply tool policy, and 12 Tool policy
status, plus 13 Initialize tool history. Named steps are `tools-init`,
`tools-review`, `tools-check`, `tools-apply`, and `tools-status`; `--review` and `--policy-digest` can supply their inputs. Guided
network setup offers initialization after network activation when no saved report
was supplied, or review of the supplied report otherwise. Network review,
signing, and activation remain separate.

## Start and change modes

```sh
nosh start --workdir "$WORKSPACE" --tool-mode read-only
nosh recreate --workdir "$WORKSPACE" --tool-mode implementation
nosh tools status --workdir "$WORKSPACE" --container CONTAINER_NAME
nosh tools rollback --workdir "$WORKSPACE" --revision sha256:PREVIOUS_REVISION
```

An applied policy is discovered automatically by ordinary Docker startup and
Guard admission. Without `--tool-mode`, new containers use read-only mode.
Implementation must have been explicitly approved. Requesting a mode without an
applied policy fails. Existing containers retain their pinned revision and mode;
apply or rollback affects future containers. A pre-policy container must be
explicitly recreated. Attaching with a different requested mode also requires
recreation. Status lists the active and saved revisions, and optionally verifies
a named container and reports its pinned revision.

The feature currently supports the `dev` workload. Guard's existing network
admission requirements still apply; the tool policy grants no network access.

## What is enforced

| Resource | Read-only mode | Implementation mode |
| --- | --- | --- |
| Workspace | Read-only bind | Writable bind |
| Applied revision at `/etc/nosh/policy` | Read-only bind | Read-only bind |
| Existing project `.codex`, `.agents`, and `AGENTS` files | Read-only overlays | Read-only overlays |
| Mounted credentials and agent settings | Read-only overlays | Read-only overlays |
| Container root filesystem | Read-only | Read-only |
| Scratch and isolated Codex state | Writable | Writable |
| Private application auth state | Writable | Writable |
| Network | Existing independent network policy | Existing independent network policy |

The agent runs as the non-root workspace owner with all capabilities dropped
and no-new-privileges. Ordinary startup gates the initial workload until Docker
mount/privilege verification succeeds, including live bind inode checks through `/proc`. This
requires a local Linux Docker daemon and accessible runner PIDs; remote daemons
or inaccessible user-namespace mappings fail closed. Guard adds the same adaptation and
verification to its existing admission and release gates. Conflicting mounts,
privileged containers, devices, control sockets, implicit image volumes, host
networking, and overlapping policy/runtime storage fail closed. Nested host
mounts and symlinked or hard-linked protected configuration are conservatively
rejected; normalize these layouts before using the feature. Ordinary policy
startup currently requires an image without a custom entrypoint.

Existing host credentials/settings are mounted read-only into isolated
`CODEX_HOME`; login/config changes must be made on the host, then recreate to
refresh the mounts. Other agent homes are read-only; those agents may need
separate writable-state adapters. Application auth state keeps its existing
private per-workspace directory so operator auth reset continues to work.

## Limits

### Opt-in MCP tool filter

Ordinary Notty launches remain unfiltered. For transport-level testing, repeat
`--allow-mcp-tool` on a legacy-mode `start` or `recreate` command:

```sh
nosh recreate --security-mode legacy \
  --allow-mcp-tool list_terminals \
  --allow-mcp-tool read_terminal
```

When present, this option narrows both MCP discovery and dispatch for the Notty
terminal MCP service. A direct call to an omitted tool fails with
`TOOL_NOT_AVAILABLE`; changing an existing container requires `recreate`.
The option does not filter shell commands, collaboration coordination tools, or
tools built into Codex, Claude, or Agy. It is not populated from historical
classifications or experimental command-policy drafts.

Tool activity classifications are **informational**. Nosh does not intercept
every Codex built-in, shell, interpreter, MCP, or connector call. It cannot
universally reject unknown commands or enforce writes only by selected tools.
Implementation mode permits any process to write the workspace. Filesystem
permissions do not prevent writes to remote services using permitted network
access or credentials. New configuration paths created in a writable workspace
are not universally intercepted; only the existing protected paths are overlaid.
The immutable environment policy remains enforced even if agent settings change.

The tool API is an attribution and user-interface seam, not a security
boundary. For example, if a worker may write a JavaScript file and execute
`node`, that program can start the same child process that a command tool would
have started. Renaming, wrapping, or omitting `exec_command` does not remove the
underlying kernel capability. Security claims therefore come from the runner's
filesystem, namespace, privilege, resource, and independent network controls;
tool history helps explain intent and correlate activity.

Guard also attaches the observation-only `nosh-exec` eBPF collector before it
releases a managed runner. It records successful descendant exec transitions
for the exact runner cgroup: the kernel-reported executable reference,
PID/TID/PPID, UID/GID, observed cgroup, and timestamps. It deliberately records
no argv. The reference may retain relative spelling; a potentially truncated
maximum-length reference makes the run incomplete. Unknown executables
remain allowed and are evidence for review. Collector loss makes the evidence
run incomplete; it does not turn historical tool labels into command denies.
An expected `/usr/bin/node` observation cannot distinguish a reviewed script
from a generated `exec.js`, so interpreters must remain constrained by the
container, filesystem, credential, syscall, and network boundaries.
Executable deny enforcement is deferred until a separately reviewed kernel
enforcement design exists.

The trusted host operator and Docker daemon are outside the agent boundary.
Host root or Docker administrators can change containers and policies. Do not
expose Docker or host control access to the agent. This is containment of an
agent in Nosh, not protection against a hostile host administrator.

## Validation

Inside a development container, run the policy unit tests and review UI tests.
On a Linux Docker host, exercise actual kernel mount enforcement with an
already-built local Nosh image:

```sh
python3 scripts/tool-policy-docker-smoke.py --image nosh
```

This creates temporary test containers and a temporary test authority, probes
writes in both modes, and removes them. It never changes installed host policy,
builds Codex, pulls an image, or replays history. Run the normal Docker-backed
release audit before deploying the updated host bundle.

## History selection

```sh
nosh tools init
nosh tools init --scope repo --workdir /absolute/checkout/subdirectory
nosh tools init --scope directory --workdir /absolute/directory
nosh tools init --scope all --no-prompt
```

The default interactive choice is this directory and its subdirectories (1).
This Git checkout is choice 2 and all retained history is choice 3.
Explicit repository scope outside Git fails with a
clear error. `--codex-home` selects the local history source, and `--output-dir`
selects a new private report directory. Noninteractive initialization requires
an explicit scope. The direct Python scanner keeps its all-history default.

Selection uses the latest recorded session/turn working directory for each
request, before deduplication. It does not parse commands to guess where they
operated. Unknown locations are counted and excluded from scoped audits,
making coverage incomplete; all-history audits retain those requests. Reports
and the UI show the selected scope and exclusion counts, bound into the audit
digest. Legacy reports without scope metadata remain readable as all-history
reports. All-history means available active and archived logs, not deleted logs
or history on other machines. Historical paths are normalized without following
current symlinks; relocated checkout identities cannot reliably be reconstructed.

## Unique requests and experimental command-rule drafts

`nosh tools init` now captures original tool inputs in a private
`requests.sqlite3` sidecar. Use `--request-details none` to omit it. The legacy
direct Python invocation still omits original inputs unless passed
`--request-details original`. Inputs can contain credentials; the sidecar is
owner-only, integrity checked, and mounted read-only in the review container.
Tool outputs are not collected and recorded commands are never executed.

The UI shows each distinct tool/input/effective-working-directory combination,
with occurrence counts after copied-session deduplication. Expand a group or
use the full inventory to page through inputs, search text, filter command and
switch patterns, and inspect the original input. Static command extraction is
conservative: dynamically constructed commands remain unresolved. Input-source
labels are hints, not file authorization.

The collapsed **Experimental strict-worker simulation** supports allowed
switches, required switches, anchored `*`/`?`
patterns, option-value patterns, and Any switches. Any switches does not remove
required switches or value constraints. GNU sed drafts require `--sandbox`;
in-place editing additionally requires an implementation rule and workspace.
`xargs` is rejected by the candidate matcher because its child commands are not
mediated. File/directory-specific grants are not implemented.

Saving writes `review/command-policy-draft.json`; it does **not** activate command
enforcement. Nonempty command drafts block environment-policy approval/apply so
they cannot silently become broad shell permissions. Existing approved
environment policies retain their read-only policy mounts. No Codex executable
is modified.

Legacy schema-v1 review files remain readable. Their former Read-only,
Implementation-only, and Exclude choices are migrated in memory to the new
activity classifications while retaining the original choice as provenance;
reading an old report does not rewrite it.

## Strict runner status

`nosh tools doctor` reports host prerequisites and exits unsuccessfully while
strict enforcement is unavailable. The candidate worker uses a fixed argument
vector, a non-root Docker process, a read-only root, explicit workspace mode,
and AppArmor execution restrictions. It is a prototype, not an active security
boundary. The MCP broker, strict agent confinement, startup integration, and
complete live bypass acceptance suite remain unfinished.

For development on a Linux Docker/AppArmor host, build the isolated probe image:

```sh
docker build -f Dockerfile.command-probe -t nosh-command-probe .
docker image inspect --format '{{.Id}}' nosh-command-probe
sudo node scripts/command-runner-host-probe.mjs sha256:EXACT_IMAGE_ID
```

The probe temporarily loads AppArmor profiles and runs disposable containers.
It tests a sed stream, subprocess denial, and a read-only workspace; even a
successful probe does not authorize activation. It does not exercise the missing
agent/broker boundary, alternate loaders, or the full pipeline lifecycle.
