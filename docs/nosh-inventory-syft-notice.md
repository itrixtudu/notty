# Offline inventory attribution and scope

`scripts/nosh-inventory.py` adapts selected package-metadata handling concepts and
logic from Anchore Syft v1.50.0, local source commit
`16223e6dd7893fe578787658ceb876257483d404`:

- `syft/pkg/cataloger/javascript/parse_package_lock.go` and `package.go`: npm
  lockfile versions, nested dependencies, aliases and development dependencies.
- `syft/pkg/cataloger/debian/parse_dpkg_db.go`: paragraph fields, continuations
  and installed-package status metadata.
- `syft/pkg/cataloger/python/parse_wheel_egg_metadata.go` and `cataloger.go`:
  installed Python metadata locations, folded fields and repeated headers.

Upstream attribution: Anchore Syft and its contributors. Syft is distributed
under the Apache License, Version 2.0. The full license accompanies this notice in
`nosh-inventory-syft-LICENSE`. This Python adaptation is modified for Nosh and
distributed under Apache-2.0. Other Notty files retain their existing licenses.
No Syft executable, Go dependency tree or third-party package fixtures are
bundled. Regression fixtures in `tests/nosh-inventory.test.py` were created for
Nosh rather than copied from third-party packages.

The adaptation uses Python's standard library, bounded offline reads, and
explicit collection gaps. It adds final-line handling, duplicate/oversize
metadata rejection, snapshot hashes and non-extracting archive reads. It does
not run package scripts, import workload modules, resolve requirements online,
or infer executable versions by running binaries.

“Complete” means supported package metadata was collected without a reported
coverage failure for the declared input and exclusions. It does not mean that
every executable or dependency was identified or that the software is safe.
Copied projects and declared source dependencies are labeled separately from
installed package metadata. Node, Antigravity, Ollama and other standalone
binaries may fall outside package metadata coverage. Execution allowlisting
and executable-integrity enforcement are separate work.
