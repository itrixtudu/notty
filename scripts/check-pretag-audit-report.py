#!/usr/bin/env python3
"""Accept a release audit only when the candidate tag is its sole failed gate."""

import os
import re
import stat
import sys
from pathlib import Path
from typing import Dict, Optional


EXPECTED_GATES = {
    "Required host tools",
    "Docker daemon availability",
    "Git whitespace checks",
    "Clean Git worktree",
    "RELEASE.md version and exact release tag",
    "Digest-pinned audit image",
    "Ephemeral audit volume and network",
    "Captured-commit source archive and SHA-256",
    "Networked phases bound to captured manifests",
    "Manifest-only dependency acquisition",
    "Production dependency advisory audit",
    "Offline metadata, release files, rebuild, tests, build, and package verification",
    "Offline full-checkout package leak inventory",
    "Repository and audit inputs stable for the run",
    "Ephemeral audit object cleanup",
}
TAG_GATE = "RELEASE.md version and exact release tag"


def reject(message: str) -> int:
    print(f"pretag audit: {message}", file=sys.stderr)
    return 1


def report_field(report: str, label: str) -> Optional[str]:
    matches = re.findall(
        rf"^- {re.escape(label)}: ` ([^`\n]+) `\s*$",
        report,
        flags=re.MULTILINE,
    )
    return matches[0] if len(matches) == 1 else None


def main() -> int:
    if len(sys.argv) != 2:
        return reject("usage: check-pretag-audit-report.py REPORT")

    report_path = Path(sys.argv[1])
    report_fd = -1
    try:
        report_fd = os.open(
            report_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        if not stat.S_ISREG(os.fstat(report_fd).st_mode):
            os.close(report_fd)
            report_fd = -1
            return reject(f"report is not a regular file: {report_path}")
        with os.fdopen(report_fd, "r", encoding="utf-8") as report_file:
            report_fd = -1
            report = report_file.read()
    except (OSError, UnicodeError) as error:
        return reject(f"could not read {report_path}: {error}")
    finally:
        if report_fd >= 0:
            os.close(report_fd)

    title = "# Notty Release Audit Report\n\n"
    if not report.startswith(title) or report.count(title) != 1:
        return reject("report title is missing or duplicated")
    outcome_pattern = re.compile(
        r"^> Outcome: \*\*(PASS|FAIL|INCOMPLETE|INTERRUPTED)\*\* "
        r"\(exit status `([0-9]+)`\)$",
        flags=re.MULTILINE,
    )
    outcomes = outcome_pattern.findall(report)
    if len(outcomes) != 1 or not outcome_pattern.match(report[len(title):]):
        return reject("report outcome is missing, misplaced, or duplicated")
    if outcomes[0] != ("FAIL", "1"):
        return reject("report does not record a completed exit-status-1 audit")

    headings = [
        "\n## Run identity\n",
        "\n## Repository worktree\n",
        "\n## Automated gates\n",
        "\n### Passed\n",
        "\n### Failed or incomplete\n",
        "\n### Warnings\n",
        "\n## Manual gates (not evaluated)\n",
    ]
    heading_positions = []
    for heading in headings:
        if report.count(heading) != 1:
            return reject(f"report heading is missing or duplicated: {heading.strip()}")
        heading_positions.append(report.find(heading))
    if heading_positions != sorted(heading_positions):
        return reject("report sections are out of order")

    section_start = heading_positions[2]
    section_end = heading_positions[3]

    gate_pattern = re.compile(
        r"- \[([ x])\] `(PASS|FAIL|SKIPPED|NOT RUN)` - (.+)"
    )
    gates: Dict[str, str] = {}
    gate_section = report[
        section_start + len("\n## Automated gates\n"):section_end
    ]
    for raw_line in gate_section.splitlines():
        if not raw_line:
            continue
        match = gate_pattern.fullmatch(raw_line)
        if not match:
            return reject(f"malformed automated-gate row: {raw_line!r}")
        checkbox, state, label = match.groups()
        if label in gates:
            return reject(f"duplicate automated gate: {label}")
        if (checkbox == "x") != (state == "PASS"):
            return reject(f"checkbox and state disagree for gate: {label}")
        gates[label] = state

    if set(gates) != EXPECTED_GATES:
        missing = sorted(EXPECTED_GATES - set(gates))
        unexpected = sorted(set(gates) - EXPECTED_GATES)
        return reject(
            f"automated gate set changed; missing={missing}, unexpected={unexpected}"
        )
    if gates[TAG_GATE] != "FAIL":
        return reject(f"candidate tag gate is {gates[TAG_GATE]}, not FAIL")

    other_failures = {
        label: state
        for label, state in gates.items()
        if label != TAG_GATE and state != "PASS"
    }
    if other_failures:
        return reject(f"non-tag automated gates are incomplete: {other_failures}")

    candidate = report_field(report, "Release candidate at captured commit")
    package_version = report_field(report, "Package version at captured commit")
    if not candidate or candidate == "unavailable":
        return reject("release candidate is unavailable, missing, or duplicated")
    if not package_version:
        return reject("package version is missing or duplicated")
    identity_section = report[heading_positions[0]:heading_positions[1]]
    if report_field(identity_section, "Release candidate at captured commit") != candidate:
        return reject("release candidate is outside the run-identity section")
    if report_field(identity_section, "Package version at captured commit") != package_version:
        return reject("package version is outside the run-identity section")
    if package_version != candidate:
        return reject(
            f"package version {package_version!r} does not equal candidate {candidate!r}"
        )
    expected_failure = (
        f"captured commit lacks release tag {candidate} or v{candidate}"
    )
    failed_header = headings[4]
    failed_start = heading_positions[4]
    failed_end = heading_positions[5]

    failure_pattern = re.compile(r"- \[ \] ` ([^`\n]+) `")
    failures = []
    failed_section = report[failed_start + len(failed_header):failed_end]
    for raw_line in failed_section.splitlines():
        if not raw_line:
            continue
        match = failure_pattern.fullmatch(raw_line)
        if not match:
            return reject(f"malformed failed-or-incomplete row: {raw_line!r}")
        failures.append(match.group(1))
    if failures != [expected_failure]:
        return reject(
            "failed-or-incomplete details are not exactly the absent-tag failure: "
            f"{failures!r}"
        )

    print(
        f"pretag audit: every automated gate passed except the missing {candidate} tag"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
