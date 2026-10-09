# Repository setup profiles

`nosh config` opens a browser setup page for the current checked-out repository.
It saves build, dev/run, and tool environment settings and generates commands to
copy into a **host terminal**. Saving a profile does not execute commands, grant
permissions, sign a review, or change an active policy. `nosh init` remains
available as the terminal wizard.

## Open setup

Use the updated launcher and a locally built review image containing setup ABI 1.
On the Docker host, as your normal Docker-authorized user:

```sh
docker build -t nosh-policy-review:managed policy-review
export NOSH_POLICY_REVIEW_UI_IMAGE="$(docker image inspect --format '{{.Id}}' nosh-policy-review:managed)"
./scripts/nosh.sh config --workdir /absolute/path/to/repository
```

After launcher installation, use `nosh config`. `--no-browser` prints the private
URL without opening it. Existing private launcher/image/network configuration
seeds a new profile. A profile's saved review image takes precedence over the
launcher environment; images are always exact local IDs, checked for ABI 1,
and launched with `--pull never`. The launcher prints a stop command.

The setup container listens only on loopback, requires its session token, runs
as the invoking user without capabilities, and has a read-only root filesystem.
Its only persistent writable mount is this repository's configuration directory.
Host status and workspace bindings are mounted read-only. It has no workspace,
Docker socket, agent credentials, or signing-key mounts. Profile input is data;
the browser API cannot execute a host command or accept arbitrary shell hooks.

The sections cover:

- **Repository & host:** Guard installation, launchers, exact tooling/UI images,
  network inspection, reserved review pool and LAN/VPN exclusions.
- **Build / CI:** Dockerfile/context paths relative to the repository, target,
  platform, non-secret build arguments, output, collection mode and saved evidence.
- **Runtime:** independent dev and run images, app startup, duration, and dev
  agent homes, presets and pinned baseline references.
- **Tools:** audit report, environment-policy digest and requested read/write mode.
- **Review & activation:** existing managed review launchers, inventories,
  prerequisites, signing, digest-bound apply commands and observed status.
- **Launch & export:** enforced or explicitly legacy launches and portable settings.

Choose **Save profile** before copying commands; commands always describe the
last saved revision. Save conflicts retain your edits and require reloading the
newer profile. After running a command on the host:

```sh
nosh config refresh --workdir /absolute/path/to/repository
```

Then choose **Reload status** in the page. Ordinary refresh performs read-only
local discovery. To explicitly ask for sudo and read installed Guard activation:

```sh
nosh config refresh --privileged --workdir /absolute/path/to/repository
```

The snapshot records its timestamp and profile revision. It is an informational
last check, never an authorization token. Apply and launch verify current policy
again. A local image is not proof of a completed build capture. Saved build
candidate references are labeled unverified and do not establish that today's
Dockerfile, dependencies, source, or settings were captured.

## Privileged steps and policy boundaries

Copied runtime commands use `nosh config runtime --operation learn|enforce`
with the workspace, workload and exact saved profile revision. The host verifies
the canonical workspace identity and installed root-owned Guard executable and
its ancestors before invoking sudo. Changed settings invalidate older copied
runtime commands. No whole build, setup page, or mutable checkout is elevated.
The Guard installer still follows `nosh init`'s build, checksum verification and
explicit installer-confirmation sequence.

Network learning always uses clean builds. Cache mode and depth apply only to
`build profile`. Managed mitmproxy capture currently produces diagnostic-only
evidence because its existing provenance gap remains blocking. No configuration
selection removes an evidence or activation blocker.

Build evidence does not grant runtime network access. Dev and run reviews remain
separate. Tool selections are informational; the approved tool **environment**
policy enforces container filesystem access for dev workloads. Read-only is the
default. Implementation must be explicitly approved in Tool Review; selecting
that mode in setup cannot grant it. Enforced runtime commands use the existing
`net enforce` workflow and never fall back to legacy launch.

Network sessions have no `recreate` command: exit the existing guarded session,
let Guard complete cleanup, and start another enforced session. For ordinary
containers, setup generates the existing explicit `nosh recreate` command.

## Storage and portability

Configuration is private, caller-owned JSON beneath:

```text
${XDG_CONFIG_HOME:-~/.config}/nosh/repositories/<workspace-key>/profile.json
${XDG_STATE_HOME:-~/.local/state}/nosh/repositories/<workspace-key>/binding.json
${XDG_STATE_HOME:-~/.local/state}/nosh/repositories/<workspace-key>/snapshot.json
```

The key uses the existing canonical-path SHA-256 convention. Bindings also record
the workspace device and inode. Replacing a checkout at the same path requires
explicit import to bind fresh configuration; it never transfers policy approval.
Configuration and state must be separate private locations outside the workload.
Signing, review artifacts, evidence and root-owned active policy stores remain
in their existing locations.

```sh
nosh config export --workdir /path/to/source > nosh-config.json
nosh config import --profile nosh-config.json --workdir /path/to/destination
```

Exports contain versioned portable settings, including relative build and
baseline paths. They omit host bindings, report paths, review/activation state,
image-tooling configuration, credentials and signing configuration. Imports
replace portable settings, reset host references, and refresh discovery; review
and activation remain explicit. This profile is distinct from `--profile` mount
presets.

Build arguments must contain no secrets. Obvious secret-bearing argument names
are rejected, but the tool cannot infer whether an arbitrary value is sensitive.
Review exports before committing or sharing them; use existing external secret
and credential delivery rather than storing credentials in settings.

## CI/CD capture

Provision the Linux runner separately with Docker, Buildx, Guard, kernel/eBPF
support and the reviewed narrow build-session authorization. The optional
installer-managed sudoers rule authorizes only the build collector lifecycle;
it does not grant runtime or policy activation rights. See
[build profiling](nosh-build-profiling.md) for runner prerequisites.

Run as the normal Docker-authorized user, not root:

```sh
nosh config ci --profile nosh-config.json --workdir "$PWD" \
  --output-dir "$PWD/ci-evidence"
```

The artifact directory must be new. The command uses the existing build capture
workflow and sets `NOSH_BUILD_NONINTERACTIVE=1`, making collector sudo calls use
`-n`. Missing authorization fails promptly. No browser, automatic provisioning,
policy approval, deployment, or unmeasured fallback is started.

`result.json` contains the portable configuration digest, available image and
evidence digests, timestamps, status, exit code and relative `portableDirectory`.
A successful build without complete, candidate-eligible capture fails the CI
step. Build failures retain their exit code and available portable artifacts.
A failed collector can return its preserved bundle through private JSON so CI
can retain diagnostic evidence without printing private paths into public JSON.

Upload **only** `result.json` and the indicated `portable/` directory, including
after failed captures when present. Raw capture JSON and stderr stay in a private
per-invocation directory beneath XDG state (`nosh/config-ci`); its location is
printed on stderr for the operator. Artifacts are observational, not approvals.
Changing CI environment, platform, Dockerfile, target or dependencies requires a
new capture and any applicable review. Provider-specific workflow generation and
build-network enforcement are outside this initial configuration tool.

## Validation

All package-manager commands run inside containers. In a development container:

```sh
node --test tests/nosh-config.test.cjs tests/build-orchestrator.test.cjs tests/build-guard-api-cli.test.cjs
cd policy-review
npm run test:run
npm run build
```

Optional browser validation, from the repository root in the same container:

```sh
NOSH_PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs node scripts/setup-browser-smoke.mjs
```

The smoke uses synthetic state and checks save/reload, failed-save recovery,
conflicting revisions, command quoting, keyboard focus and mobile overflow. It
writes screenshots to `/tmp/nosh-setup-screenshots` (override with
`NOSH_SETUP_SCREENSHOTS`). It never performs a host action or activates policy.
Synthetic verification screenshots: [desktop](images/nosh-setup-desktop.png) and
[mobile](images/nosh-setup-mobile.png).
On a Docker host, also run `./scripts/release-audit.sh` and exercise real
learning/review/apply/launch on a provisioned Guard machine.
