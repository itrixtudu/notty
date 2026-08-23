# Contributing to Notty

Thank you for helping improve Notty. This repository accepts focused,
maintainer-coordinated contributions.

## Start With an Issue

Before beginning any contribution, open an issue describing the problem,
proposed outcome, and intended testing. Wait for a maintainer to agree on the
work and assign the target branch before writing or submitting the change. Do
not assume the default branch is the correct target.

Potential vulnerabilities are the exception: report them privately as
described in [SECURITY.md](SECURITY.md), never in a public issue.

Agreement on an issue is not a guarantee that a pull request will be merged.
Keep the implementation within the agreed scope, and discuss material design or
scope changes on the issue before proceeding.

## License and Third-Party Material

By submitting a contribution, you agree to license it under the project's
[0BSD license](LICENSE). Notty does not require a Contributor License Agreement
(CLA) or Developer Certificate of Origin (DCO).

Submit only work you have the right to contribute. Do not add copied source,
artwork, fonts, binaries, model output, or other third-party material unless a
maintainer approved it in the issue and its origin, license, attribution, and
redistribution terms are documented.

## Development and Validation

Never run `npm`, `npx`, or `npm exec` on the host system. Package installation,
tests, builds, audits, and packaging belong inside containers. Run normal
application and test `node` commands from an attached Nosh container; the
separately documented root-owned Guard prototype remains subject to its own
host preflight and reviewed-bundle requirements.

From the host, the release baseline is:

```sh
./release-audit.sh
```

Docker is mandatory and the audit has no host-package-manager fallback. Build
and enter the normal development environment with `./build-nosh.sh` and
`./nosh.sh`. Package scripts and targeted Node.js tests may be run only from an
attached Nosh container. `bash scripts/test.sh` provides the Docker-backed MCP
terminal flow from the host. Pull-request CI runs the same Docker release audit
and accepts an untagged commit only when its report proves that the missing
candidate tag is the sole failed automated gate. CI checkout and whitespace
checks use host Git; the workflow has no JavaScript actions or host Node.js
package work.

When an approved dependency change requires a new lockfile, edit and review
`package.json`, then run `./regenerate-package-lock.sh` on the host. That
wrapper passes only the manifest to a locked-down Docker container, disables
lifecycle scripts and non-registry sources, rejects production advisories, and
validates the candidate offline before replacing the lock atomically. It never
runs a host package manager or repairs the old lock in place. Review and commit
both manifests before running `./release-audit.sh`; the audit intentionally
rejects a dirty checkout. Use `--replace-dirty-lock` only to discard previously
reviewed uncommitted lockfile output.

Follow the existing local style: modern ES modules, two-space JavaScript
indentation, descriptive camelCase variables and functions, PascalCase React
components, and kebab-case shell scripts. Avoid unrelated formatting or
cleanup.

Security-control changes must include focused regression coverage in the same
pull request. Exercise HTTP and SSE paths for terminal or MCP behavior when
practical. Never put OAuth tokens, provider credentials, spawn OTPs, terminal
secrets, or local host overrides in commits, fixtures, screenshots, logs, or
pull-request text.

## Commits and Pull Requests

Keep commits focused and use short, imperative subjects. A pull request must:

- link the agreed issue and target the branch assigned by a maintainer;
- explain the user-visible or operational behavior changed;
- list the exact validation commands run and their results;
- note Docker, environment, migration, and compatibility assumptions;
- include screenshots or a short scrubbed recording for visible UI changes;
- describe focused security tests when a trust boundary or control changes;
- update `CHANGELOG.md` under `[Unreleased]` for user- or operator-visible
  behavior, security, compatibility, packaging, or operational changes; and
- disclose any new dependency or third-party material with its provenance and
  license.

Keep internal-only refactors out of the changelog. Maintainers may request that
a large change be split into independently reviewable pull requests.

## Respectful Collaboration

Treat contributors, users, and maintainers with patience and respect. Welcome
questions and differing technical opinions; critique ideas and code rather than
people. Harassment, threats, discriminatory language, sexualized attention,
doxxing, deliberate disruption, and publication of another person's private
information are not acceptable in project spaces.

Maintainers interpret and enforce these expectations. Depending on context and
severity, they may edit or remove content, close or lock discussions, reject
contributions, issue a warning, or temporarily or permanently restrict
participation. Report conduct concerns privately to a maintainer using an
available private GitHub contact method, and use GitHub's platform reporting
tools for urgent safety or platform-policy concerns. Do not publish sensitive
conduct reports in an issue. Maintainers should limit disclosure to the people
needed to review and address the report and should avoid conflicts of interest.
