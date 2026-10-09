# Initialize a workspace, then start or attach

To remove Nosh, use `nosh uninstall`. It previews verified per-user files first
and treats privileged Guard removal as a separate confirmation. See the
[Debian package and uninstall guide](docs/nosh-debian-package.md); policy,
evidence, signing state, Docker data, and repository configuration are preserved
unless an explicit purge option applies to them.

For browser-based saved repository settings, use `nosh config`. It generates
copyable host commands for this workflow and provides portable CI configuration.
See [repository setup profiles](docs/nosh-repository-config.md). The terminal
wizard below remains available independently.

Run `nosh init` in the project you want to configure. Before the launcher is
installed, use `/path/to/notty/scripts/nosh.sh init`. On an interactive host
terminal this opens the resumable Textual setup wizard. The default Guided view
sets up **one image at a time**, with full-width pages for **Choose image → Build
→ Development (Dev) → Application runtime (Run) → Finish**. Select the image,
then use **Previous**, **Skip**, and **Next**. The **Advanced** view retains the
dashboard and remaining-action queue, including QEMU and tool-policy setup.
Both views discover the base and derived `Dockerfile.nosh-*` workload images and
refresh verified state after every command:

```bash
nosh init
```

Preview without executing commands: `nosh init --dry-run`.
For another checkout: `nosh init --workdir /absolute/path/to/repository`.
The page header always identifies **Workspace**, **Image**, and **Policy**.
Workspace and Policy labels are bold cyan; the Image label is bold magenta.
Build is yellow, Dev is blue, and Run is red. These identify the policy, not
success or failure. The Next tip stays below the header, outside scrolling content.
The bottom row contains More…, Previous, Skip, and Next; More… contains Details,
Recheck, Advanced, and Manage Policies. Saved recordings have a Record again
button in their page content.
Completed work is green, unfinished or failed work is red, attention is amber,
and skipped work is gray. Status text accompanies each
color. There is no progress sidebar or changing total step count. Use the visible
controls with the mouse or Tab/Enter; Space operates only the focused control.
In Guided mode, **N** is Next, **P** is Previous, and **S** is Skip (lowercase
works too). Escape also goes back. While typing in a text field, letters remain
text input; Tab out to use the shortcuts. Advanced retains `p` for Preflight and
`s` for Save refs.

Each page explains what **Next** will do before it runs that action. The wizard
advances after verification; a failed action stays on its page for retry.
**Previous** reviews earlier pages without running commands or undoing work.
Already-completed pages say so and continue without rerunning. **Skip** also skips
dependent work when no valid prerequisite exists, but leaves independent stages
available. **Details** shows the command; its output appears in the interactive
terminal, and the Advanced dashboard retains an action log. Privileged and
signing operations retain necessary confirmations.

### Manage policies without restarting setup

Choose **More… → Manage Policies**, or **Open policy editor…** on a review page.
The hub offers Build Network, Dev Network, Run Network, and Dev Tools. Network
reviews identify the workspace, image ID, and saved recording revision. Tool
policies are Dev-only, workspace-wide container filesystem permissions, not
executable allowlists. Opening the hub cancels any queued automatic capture;
Return to setup preserves the current page without executing it.

Use **Open in browser** for the existing Docker-backed React editor. The launcher
prints a copyable local URL if automatic browser opening is unavailable. Keep
that capability URL private; the wizard does not save it in project references.
The launcher may build its review UI after confirmation. Missing host tooling,
review networking, or signing must be addressed explicitly through setup.

Save decisions in the browser, return, and **Verify status** to refresh discovery.
Select the saved review, **Validate**, then **Apply** the exact digest after
confirmation. Saving or closing the browser never implies activation. Apply
rechecks saved decisions and checks the resulting activation; changes affect
future containers and never automatically recreate running containers. Build
captures are review evidence only, so their Validate/Apply controls are disabled.

Dev Tools discovers workspace-scoped private reports in the standard audit
directory and any explicit `--review` path. Multiple reports require selection;
**Load report** accepts another scoped private report directory. **Initialize
history** explicitly audits repo scope when inside Git, otherwise directory
scope—never all history. Missing network evidence offers **Go to recording**;
that navigation alone does not start capture. Skip preserves existing policies.

On the Build page, reuse a compatible existing image, build it, or build it while
capturing network activity. Reuse is the default for a compatible existing image;
a new image defaults to build with capture. Capture performs the build once,
then offers its results and a separate review page. Required base-image builds
are prerequisites of the selected image. Build traffic is evidence, not an
activated Dev or Run policy.

Why capture? Dependencies and install scripts can contact external services while
building. The recording gives you evidence to review unexpected destinations
before promoting an image through CI/CD. For example, Shai-Hulud used malicious
package install scripts to steal secrets and spread through the npm ecosystem.
See [GitHub's account of the attack](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/).

This is an extra layer of visibility, not a cure-all: recording does not
automatically detect or block malware, and malicious traffic can succeed during
capture. Dormant behavior and abuse of normally trusted services can escape
notice; a clean recording is not proof of safety. Keep production secrets out of
untrusted builds, restrict CI credentials, and review dependencies as well as the
captured evidence. Any network enforcement is a separate reviewed-policy step.

Dev and Run open directly on their recording pages, with no separate stage
introduction. **Next** requests capture and **Skip** declines the workload.
If Guard or runtime networking needs setup, Next guides you through the required
pages first, then starts capture automatically after they succeed. There is no
second capture confirmation. Previous, Skip, a failure, an image change, or
switching to Advanced cancels that pending capture; Recheck alone never starts it.
A matching saved runtime profile is reused by Next; **Record again** explicitly
requests another capture and uses the same prerequisite checks.
Before recording, the page identifies the image and workload and offers
**Start bundled application during recording** (off for Dev, on for Run).
Choose **Skip recording** to leave that workload unrequested and
continue to the next stage without inventory, review, signing, or policy changes
for the skipped workload. Skipping Dev recording still lets you set up Run.
Skip also works when a saved recording is marked complete: existing recordings
and policies are retained. Previous, then Next resumes that workload and reuses
the saved recording without recording again.
Exercise the intended workload in the interactive shell, then type **exit** to
finish recording and return to the wizard. Results, review, Apply, and verification
are separate pages. Returning from review without completing it leaves that step
unfinished.

Finish reports each stage separately. **Not requested** means the stage was
declined; **Requested but unfinished** means work remains. Declining Run does not
make completed Dev setup fail. Choose **Another image** to repeat setup
for a different image with freshly detected state.

Use `nosh init --classic` for the original guided prompts or `--advanced` for
the numbered menu. Named `--step`, `--check`, `--dry-run`, and noninteractive
interfaces do not require the TUI.
The Guided wizard introduces host setup, review networking, policy tools,
inventories, signing, and runtime readiness when first needed, reusing verified
prerequisites across stages and images. A missing prerequisite explains the
action needed; rerun `nosh init` to resume. Choose `nosh init --advanced` for the
numbered menu, or `--step STEP` for one action.
Signing setup generates separate keys offline and asks before installing public
host trust. Classic guided learning leaves the bundled app stopped; run the
workload commands you want to observe inside the shell.

Saved work is discovered automatically. For read-only detection hints:

```bash
nosh init --check
```

Detection uses Python 3's standard library and read-only local Docker/file checks;
without Python, choose steps manually. `present`, `configured`, and `saved` are
completion hints, not policy authorization. An existing image does not prove a
completed build profile. Step 8 explicitly asks for sudo to check current
workspace activation; saved receipts never prove active enforcement. These
checks do not load private key contents, install anything, or start containers.
The Guided image chooser shows local availability, and learning uses that image's
exact local ID. A new build refreshes the identity and requires matching runtime
evidence. In classic and named-step flows, `--image TAG_OR_ID` overrides automatic
selection; otherwise saved learning images and the local `nosh` tag are preferred.

Run commands in a **host terminal**, as your normal Docker-authorized user.
The workspace defaults to your current directory; `--workdir` overrides it.
Builds and tooling use containers;
never run npm on the host. Installation/builds can download dependencies.

The wizard checks policy tools in a temporary offline container. If they are
missing or outdated, it offers to build them from this checkout, verifies the
result, remembers its exact image ID, and continues. This build may download
dependencies. Saved workload images, learning, and signing keys are retained;
unchanged review choices can be restored as a draft for fresh acknowledgement.
No image ID or environment variable needs to be copied. An explicitly configured
review UI image remains a separate selection.

The host wizard uses Textual in the isolated environment at
`${XDG_DATA_HOME:-$HOME/.local/share}/nosh/tui/venv-v1`. It asks before creating
or updating that environment and installs only the exact hashed dependencies in
`config/nosh-tui-requirements.txt`. If Python's `venv` support is unavailable or
installation is declined, setup can continue through the classic wizard. The
bootstrap refuses an `XDG_DATA_HOME` or home-derived TUI path inside either the
Nosh checkout or the selected workspace, so it cannot collide with a project
`.venv` or other repository-local environment.

Before runtime learning, Guided setup has a dedicated **Host readiness** step.
It reports IPv6 enabled state, forwarding, the non-loopback default route, and
router-advertisement handling, followed by the exact-image Guard/eBPF doctor.
The wizard never changes sysctls or firewall rules. A blocked page prints the
operator command and waits for **Recheck**. Run the same check separately with:

```bash
nosh init --step readiness --image IMAGE
```

Scoped runtime policy uses a dual-stack Docker bridge, so this requirement does
not apply merely to opening the TUI or configuring launchers. If enabling IPv6
forwarding removes an RA-learned default route, set `accept_ra=2` on that uplink
before rechecking and make the reviewed settings persistent under
`/etc/sysctl.d`; enabling forwarding does not replace host firewall policy.

The Advanced dashboard presents four independent lanes: build-network evidence,
dev runtime network policy, run runtime network policy, and the optional dev-only
tool environment policy. Build-network evidence can be reviewed but is not
presented as an applied runtime policy. Guided setup instead offers Build, Dev,
and Run on their own pages; choosing an image does not enable a runtime stage.

Its environment selector supports Docker, QEMU, or both. Docker owns the image
and policy lanes described above. Selecting QEMU queues provisioning/start and
status for the persistent VM backend; selecting both retains the Docker policy
queue and adds the QEMU lifecycle actions. The `bwrap` choice is visible but
disabled until that launcher backend is implemented.

Finish saves the current image's choices in `.nosh/project.json`, retaining other
images' choices and policy references. In Advanced, press `s` to preview and save
the current choices. This portable manifest is intended for version control. It
records the selected environments, relative workload Dockerfiles, enabled policy
lanes, preflight/tool-profile choices, and available immutable references from
the latest refresh: exact image digests, learning revisions, reviewed decision
digests, and the applied tool-policy digest. On a later run the TUI restores the
saved choices and verifies their current state. In Advanced, press `g` after
learning or applying policy, then `s`, to update the references. Skipping a stage
does not delete its existing evidence or policies.

Saving is explicit and displays a unified diff first. Ordinary `nosh net learn`
and policy application never edit the checkout. The manifest does not contain
absolute host paths, review bundles, evidence, signing keys, credentials, network
pool allocation, or a claim that a referenced policy is currently active. Those
remain in protected or user-local Nosh state and are verified again before use.
Unknown manifest fields and unsafe paths are rejected rather than ignored.

On first setup, the wizard offers up to three **checked `/26` review pools**.
Each holds eight `/29` review networks, rather than representing 64 containers
on one network. Enter additional LAN/VPN exclusions first, separated by commas
or spaces; include disconnected networks that the host cannot discover.
The local inspection checks Docker allocations, host routes/interfaces, declared
Docker pools and Guard's `10.240.0.0/16` reservation. No ping sweep or external
request is made. An unreadable namespace or incomplete inspection stops selection
and offers retry; sudo reads require confirmation.

In the classic prompts, press Enter to select the first suggestion, choose another
number, choose `c` for a custom canonical RFC 1918 CIDR (`/16` through `/29`), or `0`
to cancel.
No observed overlap does not establish that disconnected networks are absent.
For example, `172.17.0.0/26` is rejected when Docker owns `172.17.0.0/16`.
The wizard checks the selected range again after confirmation, immediately before
saving; a newly observed conflict leaves configuration untouched. If no suggestions
fit, custom input still requires that same successful check.

The selected pool and exclusions are saved in `~/.config/nosh/review-network.json`
(or `NOSH_REVIEW_NETWORK_CONFIG`). Existing configuration is reused without
resizing or replacement, and each actual allocation retains its collision checks.
Docker daemon settings and existing networks are unchanged. Run
`nosh init --step network` to handle this prerequisite separately. Direct wizard
review and advanced step 5 also check it before opening the review interface.

## 1. Install Guard — once, or after daemon updates

Finish active guarded sessions first; installation restarts Guard.
Use `nosh init --step install` to build and install the current Guard through
the wizard, then `nosh init` to resume saved setup work. Updating the installed
Guard is separate from rebuilding workload or policy-tooling images.

If the protected installation receipt records a different software prefix,
the wizard offers to uninstall that release before building the replacement.
It separately asks whether to purge bundle-managed configuration and whether
to permanently purge Guard evidence and state; both destructive choices
default to No. A normal prefix migration preserves configuration and evidence.

The equivalent manual installation is:

```bash
(
  set -euo pipefail
  stage=$(mktemp -d "$PWD/.nosh-install.XXXXXX")
  mkdir -m 700 "$stage/artifacts" "$stage/extracted"
  bash scripts/build-nosh-guard-host-bundle.sh --output-dir "$stage/artifacts"
  shopt -s nullglob
  archives=("$stage/artifacts/"*.tar.gz)
  [[ ${#archives[@]} == 1 ]]
  archive=${archives[0]}
  (cd "$stage/artifacts" && sha256sum --check "$(basename "$archive").sha256")
  tar -xzf "$archive" -C "$stage/extracted"
  installers=("$stage/extracted/"*/install.sh)
  [[ ${#installers[@]} == 1 ]]
  sudo bash "${installers[0]}" install --prefix /opt/notty --enable-now
)
./scripts/setup-nosh.sh --guard-prefix /opt/notty --require-guard
```

### Optional Bubble Bai Codex pet

After configuring launchers, the wizard offers to install Bubble Bai, defaulting
to No. This also applies to advanced step 2 and `nosh init --step setup`.
**Bubble Bai has only been tested in Kitty terminal. Support in other terminals
is unverified.** Declining or an installation failure does not block Nosh setup.

**Disclaimer:** Using Codex with Kitty, pets, and voice is an escape hatch
outside the coverage of the eBPF run profile. Do not treat host terminal, pet,
or voice integrations as contained or fully monitored by that profile.

To install separately from this checkout, run as your normal host user:

```sh
sh bubble-bai-codex/install.sh
```

The installer uses `${CODEX_HOME:-$HOME/.codex}/pets/bubble-bai/`, requires no sudo,
and refuses to overwrite differing pet files. See the
[Bubble Bai guide](bubble-bai-codex/README.md) for activation instructions.

## 2. Build and profile the Docker repository

Before allocating test networks, run the read-only host network preflight:

```bash
python3 -I -S scripts/nosh-network-preflight.py
# Or through the wizard:
nosh init --step preflight
```

Run as your normal host user. The script asks before sudo when unreadable daemon
metadata or Docker socket permissions require it. It inspects the selected local
Docker endpoint, daemon arguments/configuration, systemd paths, network IPAM,
interfaces and IPv4/IPv6 routes. It never changes Docker or creates a network.
This is an explicit step pending host acceptance; guided initialization does not yet
invoke it automatically.

For a saved report, use `python3 -I -S scripts/nosh-network-preflight.py --json >
network-preflight.json`. JSON mode never prompts; `--sudo` permits read-only
elevation using already available sudo credentials (`sudo -n`). Exit codes are
`0` for completed checks, `2` for conflicts/invalid configuration, and `3` for an
incomplete assessment. Reports include local topology; keep them private.
Use `--pool <CIDR>` to inspect a proposed pool without saving it. Existing Docker
allocations within that pool are listed as occupied, not free space. Default
address pools intersecting host networks generate warnings, not a claim that a
collision has already occurred. Missing/null daemon pool information stays
unknown. Disconnected LAN/VPN ranges still require operator exclusions in the
review network configuration.

`bip` controls Docker's default bridge; user-defined networks use default address
pools or explicit subnets. Existing network allocations persist independently of
later configuration edits. The usual rootful configuration is
`/etc/docker/daemon.json`, but the preflight discovers `--config-file` and systemd
unit/drop-in paths rather than assuming them. Rootless, remote or unmatched
daemon namespaces are reported as incomplete.

For this repository (`Dockerfile.nosh`):

```bash
IMAGE_NAME=nosh ./scripts/build-nosh.sh net learn
IMAGE=$(docker image inspect --format '{{.Id}}' nosh)
WORKSPACE=$PWD
```

This captures a clean build and opens build review. The Guided wizard suppresses
automatic review so it can show capture results and offer review on its own page.
**Build traffic is not a runtime allowlist.** Continue with runtime learning below.

For another already-checked-out Docker repository, the build command is:

```bash
WORKSPACE=/absolute/path/to/repository
./scripts/nosh.sh build net learn --file "$WORKSPACE/Dockerfile" \
  --tag profiled-app:local "$WORKSPACE"
IMAGE=$(docker image inspect --format '{{.Id}}' profiled-app:local)
```

Runtime learning requires a [Guard-compatible runner image](docs/nosh-guard.md#guarded-runner-abi);
an arbitrary Docker image is not automatically compatible. Other repositories
also need separately configured trusted review/tooling images.

## 3. Learn runtime traffic

Learning defaults to **dev**, reusing the invoking user's available Codex, Claude,
and Gemini homes. Use `--workload run` for app-only learning without agent
homes. The selected workload carries through review, apply, and status. See
[workload profiles](docs/nosh-workloads.md) for agent selection and pinned
network baselines. Reprofile existing experimental workloads using dev or run.

Interactive `nosh` (or `nosh start`) first attaches to an existing running
project container. For a new launch with a saved profile, it asks **Run with existing policy [Y/n]**. Decline to get **Profile new run [Y/n]**;
decline again to get **Run without policy [Y/n]**. Declining all three exits.
Enter accepts the current prompt. Guard checks the applied policy with your permission
for sudo, then shows its exact image and revision and launches it.
You do not need to copy a UUID. A draft alone cannot be enforced: finish `nosh init`.

Choosing without policy explicitly uses the normal launcher and retains your
saved policy. Profiling uses the learning wizard; it does not replace the applied
policy until you review and apply the new results. Explicit `--security-mode legacy`
skips these prompts. Scripts without a terminal keep their existing behavior.
Enforcement errors never fall back to an unguarded container. A reserved run must
be resolved explicitly; the menu does not remove or attach to it automatically.
After updating these launcher features, update Guard through setup step 1 as well
to install support for checking the selected deployment at launch.

For a fresh runtime profile, leave any current container shell and run on the host:

```bash
nosh init --step learn
```

This runs `nosh init --step learn`, including image discovery and the learning
prompts. Use `nosh init --step learn --workdir /absolute/workspace` for another
workspace. Exercise your workload in the learning shell, then `exit` and run
`nosh init` to review and apply. Then use `nosh start` to launch or attach.

The direct Guard command is:

```bash
sudo /opt/notty/bin/nosh-guard net learn --workdir "$WORKSPACE" --image "$IMAGE" \
  --name "profile-$(date +%s)" --review-output --no-start-app --no-collab
```

Inside the container, exercise the commands/connections you need. Then `exit`
the attached shell to finish this learning session. Use `--start-app` instead
of `--no-start-app` to also launch the bundled service. Open runtime review in
the next step as your normal user.
Keep this command interactive: do not pipe it to `tee` or redirect it.
An interrupted session can still export evidence. The wizard retains its failure
status and asks for new learning; saved evidence alone is not a completed profile.

## 4. Review and edit

In runtime review: choose Allow/Deny, enter your reviewer identity, acknowledge
the review under **Review selections**, then **Save reviewed policy**.
Progress saves automatically; saving a reviewed policy does not activate it. To reopen later:

```bash
./scripts/nosh.sh net review --workdir "$WORKSPACE"
```

Guided setup collects inventories with local offline tooling and checks evidence
before opening review. Unavailable or incomplete inventories remain blockers.
When refreshed inventories change the review, unchanged connection choices can
be restored as a draft; new or changed proposals need review and acknowledgements
must be entered again. Previous sessions remain intact.

The displayed review directory contains `decisions/draft.json` and completed
`decisions/decisions.json`. These select observed rules; they are not an
arbitrary IP/port editor. For terminal-only JSON editing, use the
[manual decision workflow](docs/nosh-policy-review.md#cli-review-and-manual-json-edits).
Revalidate edits to regenerate their digest. Do not edit a signed policy file.

## 5. Apply the edited selection

**One-time prerequisite:** complete the Guided signing page, choose classic
advanced step **6 — Set up signing**, or run:

```bash
python3 scripts/nosh-signing-setup.py --workdir "$PWD"
```

It generates separate keys in offline containers using the existing local tooling
image, displays the public trust configuration, and asks before installing it
with sudo. Private keys stay in separate directories outside the workspace;
`~/.config/nosh/policy-apply.json` is created automatically. Existing trust and
user configuration are never replaced. If interrupted, use the printed resume
command. Keep the retained signing directory: it contains the keys used by Apply.
For an already provisioned host, use [the manual configuration](docs/nosh-policy-review.md#saved-runtime-profiles). Source and exact-image SBOMs are also required;
missing evidence can allow review but blocks activation.

After saving your final edits, continue to Guided **Apply** or choose classic
advanced step **7**: it discovers the completed
review for the selected workspace, image and learning revision, displays its path
and digest, and asks before running Apply. If several reviews match, choose one
from the numbered list. You can also copy the UI's exact **Apply command** into
the host terminal. It has this form; use the printed path and digest:

```text
./scripts/nosh.sh net apply --review <review-session-path> --decision-digest <saved-digest>
```

Review the proposed replacement and confirm. This validates, signs, and activates
the selection. Saving/downloading JSON alone does not apply it. Guided setup uses
separate Apply and verification pages before reporting stage readiness. The
classic flow prints a `nosh start --workdir …` command. The installed Guard validates
the applied policy again before a new enforced launch.

## 6. Start with enforcement

Initialization does not start the final container. To start or attach after
successful application:

```bash
nosh start
```

Attaching to an existing container preserves its current settings and policy;
newly configured settings apply to future launches. Leave and explicitly stop
the old container before launching a new enforced session.

For an explicit enforced launch with a selected workspace and revision:

```text
sudo /opt/notty/bin/nosh-guard net enforce --workdir <workspace> --revision <approved-revision>
```

Check privileged activation status:

```bash
sudo /opt/notty/bin/nosh-guard ebpf status --workload dev --workdir "$WORKSPACE" --json
```

Inside the enforced container, test one allowed and one rejected connection.
Confirm rejection with Guard deny evidence; a timeout alone is inconclusive.
Activation applies to future guarded runs of the approved workspace/image.
Existing containers keep their policy; this Guard instance has one active deployment.

If a run fails, export diagnostics from a second **host** terminal:

```bash
sudo /opt/notty/bin/nosh-guard runs > nosh-guard.runs
```

`runs` lists saved sessions; it does not start one. Crash output is recorded in
`failure.runtimeLogTail` or `quarantine.runtimeLogTail` when available.

## 7. Relax enforcement, retrain, and resume

All commands below run on the **host**, after `exit` from the current interactive
container shell. These launch new runs; they do not toggle a running container.
Do not stop `nosh-guardd` or detach BPF links as a policy-disable procedure.

For a temporary outbound-policy relaxation:

```bash
sudo /opt/notty/bin/nosh-guard net audit --workdir /home/kross/notty
```

Audit permits ordinary unmatched outbound traffic and records would-deny events.
Exact platform containment stays active. It uses the **latest learned candidate**
and its saved image/launch settings, which may differ from the active signed
policy. Audit is not a comparison against the active signed policy and does not
automatically turn observed traffic into a new candidate.

To capture changed runtime requirements:

```bash
nosh init --step learn
# Exercise the workload inside the learning container, then exit.
nosh init
```

The wizard resumes review and signed Apply. A fresh learning run creates a new
candidate; it does not replace the active policy. Reprofile the complete intended
workload, not just the last failed request. Review the new choices and apply the
result before testing again. Leave the bundled app stopped unless it is needed
for this profile; the separate `--start-app` exit issue remains under investigation.

To resume the applied policy, use the exact revision printed after Apply:

```text
sudo /opt/notty/bin/nosh-guard net enforce --workdir /home/kross/notty --revision <applied-revision>
```

Check which policy is available with:

```bash
sudo /opt/notty/bin/nosh-guard net status --workdir /home/kross/notty
```

The runtime approval binds the exact Docker image SHA-256, workspace identity and
backend. Enforcement attaches to each guarded container's cgroup; it does not
automatically cover other containers using that image. A changed image digest
requires a matching new approval. Mounted workspace contents can change without
changing the image digest; the image hash alone does not attest those contents.
The cycle is build/profile → retain the final image → runtime learn → review →
apply → enforce/test. Build traffic observations do not authorize runtime traffic.

For each enforcement test, establish a successful baseline and then check one
approved connection and one unapproved connection, with Guard deny evidence for
the latter. `curl google.com` includes DNS: exit code 6 is a resolution failure,
not proof that the destination connection was denied. To isolate a reviewed TCP
rule from DNS, use `curl --noproxy '*' --max-time 5 --resolve
<hostname>:<port>:<approved-IP> http://<hostname>:<port>/` inside the test container.
Use the actual reviewed address and port, not an old example IP. A timeout or
connection refusal alone is inconclusive. Current Guard network enforcement is
outbound; the internal/external selector and service ingress enforcement are
separate work.

## 9–13. Tool environment policy

The advanced menu includes **9 Review tools**, **10 Check tool policy**,
**11 Apply tool policy**, **12 Tool policy status**, and **13 Initialize tool history**. These append to the
existing network steps. Tool-policy setup is available in Advanced; the Guided
single-image flow covers Build, Dev, and Run. Classic setup can also offer tool
initialization after network activation or reopen a saved report when `--review`
was supplied.

```sh
nosh init --step tools-init
# Reopen an existing audit:
nosh init --step tools-review --review /absolute/audit/report
nosh init --step tools-check --review /absolute/audit/report
nosh init --step tools-apply --review /absolute/audit/report --policy-digest sha256:REVIEWED_DIGEST
nosh init --step tools-status
```

Complete the tool proposal and the separate environment approval in the browser.
Apply uses the installed Nosh authority, and new containers discover that approval
automatically. Both read-only and implementation modes keep the applied policy
read-only inside Docker. Existing containers require explicit recreation to adopt
new settings. Codex remains upstream and unchanged; filesystem capabilities are
enforced by Nosh, while individual tool selections are informational.
See [tool-policy application and limits](docs/nosh-tool-policy.md).
