# Ubuntu Debian package

The first Nosh Debian artifact combines the host `nosh` CLI and Nosh Guard in
one locally built `notty-nosh` package. It targets Ubuntu 24.04 amd64 and is
qualified for the exact running kernel used during the build. Project workload
source, `.nosh/project.json`, Docker images, containers, review evidence, and
signing material are not package-owned.

Build from a normal Docker-authorized account:

```bash
./scripts/build-nosh-deb.sh --output-dir /absolute/private/output
```

Build from a reviewed commit. The packager admits only Git-tracked files and
fails if a required CLI/TUI source is not committed; untracked files never enter
the artifact.

The host wrapper first builds the existing Guard bundle against the read-only
host BTF. It then runs Debian packaging offline in a capability-free, read-only
container. Node, npm, compilers, and Debian package tools never run on the host.
The output contains the `.deb`, a SHA-256 checksum, an SPDX 2.3 document, and a
build manifest binding the version, source revision, architecture, and kernel.

Review those files before installation, then install through apt so dependencies
and package lifecycle scripts are honored:

```bash
sudo apt install /absolute/private/output/notty-nosh_*.deb
```

The package refuses a different running kernel, missing kernel BTF, a non-amd64
host, or an unremoved legacy Guard bundle. Uninstall the legacy bundle without
purge first so `/etc/nosh-guard` and `/var/lib/nosh-guard` survive migration.
After a kernel update, build and install a fresh kernel-qualified package.

## Uninstall

For a checkout or packaged installation, start as the configured user:

```bash
nosh uninstall
```

The first confirmation removes only launchers, setup-owned user configuration,
and the isolated TUI virtual environment. It preserves policies, evidence,
signing state, Docker data, and every repository `.nosh` directory. A separate
confirmation removes Guard. For a Debian installation that phase delegates to
`apt remove notty-nosh`; direct `apt remove` has the same state-preserving
package behavior but cannot clean configuration in individual users' homes.

Automation can make the phases explicit:

```bash
nosh uninstall --user-only --yes
nosh uninstall --guard --yes
```

`--purge-config` removes Guard configuration and `--purge-state` permanently
removes `/var/lib/nosh-guard`, including evidence. These options never follow
from `--yes`; they must be written explicitly. Without them, package removal
preserves both configuration and state. A direct `apt purge notty-nosh` removes
package configuration but deliberately preserves evidence state; use
`nosh uninstall --guard --purge-state` for the separately confirmed state purge.

The initial artifact is checksummed but not repository-signed. Apt repository
publication, multi-distribution support, arm64, and portable cross-kernel builds
are later release work.
