#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Selected format-handling behavior adapted from Anchore Syft v1.50.0.
# Modified for Nosh: bounded stdlib-only parsing, offline snapshot collection,
# explicit coverage, and no package execution. See docs/nosh-inventory-syft-notice.md.
"""Collect supported package metadata without executing workload code."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import quote


VERSION = "1"
EPOCH = "1970-01-01T00:00:00Z"
ANNOTATION_PREFIX = "nosh-inventory-collection:"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024 * 1024
MAX_MEMBERS = 1_000_000
MAX_PACKAGES = 100_000
MAX_DEPTH = 64
MAX_PATH_BYTES = 4096
MAX_FIELD_BYTES = 65536
MAX_GAPS = 1000
SOURCE_EXCLUSIONS = (
    ".git", "tmp", "node_modules", "cache", ".next", ".release-audit",
    ".nosh-guard-host-bundles", ".notty-art-runs", "logs",
    "agents/active", "agents/history", "agents/intent", "agents/jobs",
    "agents/locks", "agents/logs", "agents/msgs", "agents/runs",
    "collab/intragent/channels",
)
UNSUPPORTED_LOCKS = {
    "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "deno.lock",
    "Cargo.lock", "go.mod", "go.sum", "composer.lock", "Gemfile.lock",
    "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
    "packages.lock.json", "conan.lock",
}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class CollectionError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def text(value, label, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()):
        raise CollectionError(f"{label} must be nonempty text")
    if CONTROL.search(value) or len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise CollectionError(f"{label} contains invalid or oversized text")
    return value.strip()


def normalized_path(value):
    if not isinstance(value, str) or CONTROL.search(value):
        raise CollectionError("archive path contains control characters")
    if len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise CollectionError("archive path exceeds its byte limit")
    if value.startswith(("/", "\\")) or "\\" in value or re.match(r"^[A-Za-z]:", value):
        raise CollectionError("absolute or nonportable archive path")
    pieces = value.split("/")
    if ".." in pieces:
        raise CollectionError("parent traversal in archive path")
    pieces = [piece for piece in pieces if piece and piece != "."]
    if len(pieces) > MAX_DEPTH:
        raise CollectionError("path nesting exceeds its limit")
    return "/".join(pieces)


def source_excluded(relative):
    parts = relative.split("/")
    if parts[0].startswith(".nosh-install."):
        return True
    if any(part in {".git", "node_modules", ".next", "__pycache__"} for part in parts):
        return True
    return any(relative == root or relative.startswith(root + "/") for root in SOURCE_EXCLUSIONS)


def installed_npm_path(relative):
    parts = relative.split("/")
    if "node_modules" not in parts or parts[-1] != "package.json":
        return False
    tail = parts[len(parts) - 1 - parts[::-1].index("node_modules") + 1:]
    return (len(tail) == 2 and not tail[0].startswith("@")) or (
        len(tail) == 3 and tail[0].startswith("@")
    )


def metadata_kind(relative, role):
    name = PurePosixPath(relative).name
    if name == "package.json":
        if "node_modules" in relative.split("/"):
            return "npm-installed" if role == "image" and installed_npm_path(relative) else None
        return "npm-project"
    if role == "source" and name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm-lock"
    if name == "pyproject.toml":
        return "python-project"
    if role == "source" and name in UNSUPPORTED_LOCKS:
        return "unsupported-lock"
    if role == "image":
        parts = relative.split("/")
        if relative == "lib/apk/db/installed" or relative.startswith(("var/lib/rpm/", "usr/lib/sysimage/rpm/", "var/lib/pacman/local/")):
            return "unsupported-installed"
        if relative.endswith("/lib/dpkg/status") or "/lib/dpkg/status.d/" in relative:
            return "dpkg"
        if name == "METADATA" and len(parts) > 1 and parts[-2].lower().endswith(".dist-info"):
            return "python-installed"
        if name == "PKG-INFO" and len(parts) > 1 and parts[-2].lower().endswith(".egg-info"):
            return "python-installed"
        if name.lower().endswith(".egg-info"):
            return "python-installed"
        if relative in {"etc/os-release", "usr/lib/os-release"}:
            return "os-release"
    return None


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def json_object(data):
    def invalid_constant(value):
        raise CollectionError(f"invalid JSON constant: {value}")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_json, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise CollectionError("metadata JSON must be an object")
    return value


def fields_from_lines(data, python=False):
    """Read Deb822/core-metadata headers, including the last line without LF."""
    paragraphs, fields, key = [], {}, None
    for line in data.decode("utf-8").splitlines():
        if len(line.encode("utf-8")) > MAX_FIELD_BYTES:
            raise CollectionError("metadata line exceeds its byte limit")
        if not line:
            if fields:
                paragraphs.append(fields)
                if python:
                    return paragraphs
                fields, key = {}, None
            continue
        if line[:1] in {" ", "\t"}:
            if key is None:
                raise CollectionError("metadata continuation without a field")
            fields[key][-1] += "\n" + line.strip()
            continue
        key, separator, value = line.partition(":")
        if not separator or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", key):
            raise CollectionError("malformed metadata header")
        key = key.lower()
        if key in fields and (not python or key in {"name", "version", "metadata-version"}):
            raise CollectionError(f"duplicate metadata field: {key}")
        fields.setdefault(key, []).append(value.strip())
    if fields:
        paragraphs.append(fields)
    return paragraphs


def first(fields, name, default=""):
    return fields.get(name, [default])[0]


class Inventory:
    def __init__(self, role, image_id=None):
        self.role = role
        self.image_id = image_id
        self.metadata = {}
        self.metadata_bytes = 0
        self.packages = {}
        self.gaps = []
        self.limitations = {
            "Collection covers supported package metadata; it does not identify all software, verify executable integrity, or establish trust.",
            "Package names, versions, licenses and checksums in workload metadata are declarations, not independent authenticity verification.",
        }
        self.visited = 0
        self.distro = None
        self.debian_family = False
        self.debian_records = 0

    def gap(self, code, message):
        if len(self.gaps) < MAX_GAPS:
            item = {"code": code, "message": str(message)[:4096], "blocking": True}
            if item not in self.gaps:
                self.gaps.append(item)
        elif not any(item["code"] == "gap-limit" for item in self.gaps):
            self.gaps.append({"code": "gap-limit", "message": "Additional collection errors omitted.", "blocking": True})

    def count(self):
        self.visited += 1
        if self.visited > MAX_MEMBERS:
            raise CollectionError("filesystem member count exceeds its limit")

    def add_metadata(self, relative, kind, data):
        if len(data) > MAX_FILE_BYTES:
            raise CollectionError(f"metadata file exceeds its byte limit: {relative}")
        if self.metadata_bytes + len(data) > MAX_METADATA_BYTES:
            raise CollectionError("aggregate metadata byte limit exceeded")
        self.metadata_bytes += len(data)
        self.metadata[relative] = (kind, data)

    def package(self, name, version, ecosystem, evidence, relative, allow_unknown_version=False, **details):
        name = text(name, "package name")
        version = None if version is None and allow_unknown_version else text(version, "package version")
        if ecosystem == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
        components = name.split("/") if ecosystem == "npm" else [name]
        encoded = "/".join(quote(part, safe="") for part in components)
        if ecosystem == "deb" and self.distro:
            encoded = quote(self.distro, safe="") + "/" + encoded
        purl = f"pkg:{ecosystem}/{encoded}" + (f"@{quote(version, safe='')}" if version is not None else "")
        if ecosystem == "deb" and details.get("architecture"):
            purl += "?arch=" + quote(details["architecture"], safe="")
        annotation = {"evidence": evidence, "path": relative, **details}
        if version is None:
            annotation["versionKnown"] = False
            self.limitations.add("Some copied or declared projects omit a version; their version is recorded as unknown.")
        identity = {"name": name, "version": version, "purl": purl}
        package_id = "SPDXRef-Package-" + hashlib.sha256(canonical(identity)).hexdigest()[:32]
        package_annotation = {"annotationType": "OTHER", "annotator": "Tool: nosh-inventory-1",
                              "annotationDate": EPOCH, "comment": canonical(annotation).decode("utf-8")}
        if package_id in self.packages:
            annotations = self.packages[package_id]["annotations"]
            if package_annotation not in annotations:
                annotations.append(package_annotation)
                annotations.sort(key=lambda item: item["comment"])
            return
        self.packages[package_id] = {
            "SPDXID": package_id, "name": name,
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}],
            "annotations": [package_annotation],
        }
        if version is not None:
            self.packages[package_id]["versionInfo"] = version
        if len(self.packages) > MAX_PACKAGES:
            raise CollectionError("package count exceeds its limit")

    def npm_project(self, relative, data, installed=False):
        record = json_object(data)
        # Non-package package.json files (for module type/config) are not packages.
        if not record.get("name") and not record.get("version") and not installed:
            return
        self.package(record.get("name"), record.get("version"), "npm",
                     "installed" if installed else "declared" if self.role == "source" else "copied", relative,
                     allow_unknown_version=not installed)
        if self.role == "source" and any(record.get(key) for key in ("dependencies", "devDependencies", "optionalDependencies")):
            parent = str(PurePosixPath(relative).parent)
            prefix = "" if parent == "." else parent + "/"
            # A workspace package may be covered by an ancestor's lockfile.
            candidates = [prefix]
            while prefix:
                prefix = prefix.rstrip("/").rpartition("/")[0]
                prefix = prefix + "/" if prefix else ""
                candidates.append(prefix)
            if not any(base + name in self.metadata for base in candidates for name in ("package-lock.json", "npm-shrinkwrap.json")):
                self.gap("missing-npm-lock", f"Source package dependencies have no npm lockfile: {relative}")

    def npm_lock(self, relative, data):
        record = json_object(data)
        version = record.get("lockfileVersion")
        if type(version) is not int or version not in {1, 2, 3}:
            raise CollectionError("unsupported npm lockfileVersion; expected 1, 2 or 3")
        if version == 1:
            pending = [(record.get("dependencies", {}), 0)]
            while pending:
                dependencies, depth = pending.pop()
                if depth > MAX_DEPTH or not isinstance(dependencies, dict):
                    raise CollectionError("invalid or excessively nested npm dependency tree")
                for name, item in sorted(dependencies.items()):
                    if not isinstance(item, dict):
                        raise CollectionError("npm dependency entry must be an object")
                    package_version = text(item.get("version"), "locked npm version")
                    if package_version.startswith("npm:"):
                        name, separator, package_version = package_version[4:].rpartition("@")
                        if not separator or not name:
                            raise CollectionError("malformed npm package alias")
                    if package_version.startswith(("file:", "link:", "git:", "git+", "http:", "https:")):
                        raise CollectionError("npm lock references an unresolved non-version dependency")
                    self.package(name, package_version, "npm", "declared", relative,
                                 development=bool(item.get("dev", False)))
                    if item.get("dependencies"):
                        pending.append((item["dependencies"], depth + 1))
            return
        packages = record.get("packages")
        if not isinstance(packages, dict):
            raise CollectionError("npm v2/v3 lockfile needs a packages map")
        for location, item in sorted(packages.items()):
            location = normalized_path(location)
            if not isinstance(item, dict):
                raise CollectionError("npm locked package must be an object")
            if item.get("link") is True:
                target = normalized_path(text(item.get("resolved"), "npm workspace link"))
                if target not in packages or packages[target].get("link"):
                    raise CollectionError("npm workspace link lacks an in-lockfile target")
                continue
            name = item.get("name")
            if not name and "node_modules/" in location:
                name = location.rsplit("node_modules/", 1)[1]
            if not name and location:
                candidate = str(PurePosixPath(relative).parent / location / "package.json")
                if candidate in self.metadata:
                    name = json_object(self.metadata[candidate][1]).get("name")
            if not name and not location:
                name = record.get("name")
            if not name and not item.get("version") and not location:
                continue
            self.package(name, item.get("version"), "npm", "declared", relative,
                         allow_unknown_version="node_modules/" not in location,
                         packagePath=location, development=bool(item.get("dev", False)))

    def dpkg(self, relative, data):
        for fields in fields_from_lines(data):
            # status.d contains .md5sums and other auxiliary files in distroless.
            if not first(fields, "package"):
                raise CollectionError("dpkg entry is missing Package")
            status_value = first(fields, "status")
            if not status_value and "/status.d/" not in relative:
                raise CollectionError("dpkg status entry is missing Status")
            if status_value:
                words = status_value.split()
                if len(words) != 3:
                    raise CollectionError("invalid dpkg package Status")
                if words[-1] in {"not-installed", "config-files"}:
                    continue
            self.package(first(fields, "package"), first(fields, "version"), "deb", "installed", relative,
                         architecture=first(fields, "architecture"), status=status_value or "status.d record",
                         source=first(fields, "source"))
            self.debian_records += 1

    def python_installed(self, relative, data):
        records = fields_from_lines(data, python=True)
        if not records:
            raise CollectionError("empty installed Python metadata")
        fields = records[0]
        self.package(first(fields, "name"), first(fields, "version"), "pypi", "installed", relative)

    def python_project(self, relative, data):
        record = tomllib.loads(data.decode("utf-8"))
        project = record.get("project")
        if project is None:
            if isinstance(record.get("tool"), dict) and "poetry" in record["tool"]:
                raise CollectionError("legacy Poetry project metadata is unsupported")
            return
        if not isinstance(project, dict):
            raise CollectionError("pyproject project must be a table")
        if "version" in project.get("dynamic", []):
            raise CollectionError("dynamic Python project version cannot be determined without executing code")
        self.package(project.get("name"), project.get("version"), "pypi",
                     "declared" if self.role == "source" else "copied", relative)
        if project.get("dependencies") or project.get("optional-dependencies"):
            self.limitations.add("Python project requirement ranges are declarations; resolved installed distributions are inventoried separately.")

    def parse(self):
        for candidate in ("etc/os-release", "usr/lib/os-release"):
            if candidate in self.metadata:
                release = {}
                for line in self.metadata[candidate][1].decode("utf-8").splitlines():
                    key, separator, value = line.partition("=")
                    if separator and key in {"ID", "ID_LIKE"}:
                        value = value.strip().strip("\"'")
                        release[key] = value
                    if key == "ID":
                        if re.fullmatch(r"[a-z0-9._-]+", value):
                            self.distro = value
                self.debian_family = self.distro in {"debian", "ubuntu"} or bool(
                    {"debian", "ubuntu"}.intersection(release.get("ID_LIKE", "").split())
                )
                if self.distro:
                    break
        for relative, (kind, data) in sorted(self.metadata.items()):
            try:
                if kind == "unsupported-lock":
                    self.gap("unsupported-lockfile", f"Required source dependency format is unsupported: {relative}")
                elif kind == "unsupported-installed":
                    self.gap("unsupported-package-database", f"Installed package database format is unsupported: {relative}")
                elif kind in {"npm-project", "npm-installed"}:
                    self.npm_project(relative, data, kind == "npm-installed")
                elif kind == "npm-lock":
                    shrinkwrap = str(PurePosixPath(relative).parent / "npm-shrinkwrap.json")
                    if PurePosixPath(relative).name != "package-lock.json" or shrinkwrap not in self.metadata:
                        self.npm_lock(relative, data)
                elif kind == "dpkg":
                    self.dpkg(relative, data)
                elif kind == "python-installed":
                    self.python_installed(relative, data)
                elif kind == "python-project":
                    self.python_project(relative, data)
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
                self.gap("metadata-invalid", f"{relative}: {error}")
        if self.role == "image" and self.debian_family:
            if not any(kind == "dpkg" for kind, _ in self.metadata.values()):
                self.gap("dpkg-database-missing", "Debian-family image declares its OS but has no readable dpkg status database.")
            elif self.debian_records == 0:
                self.gap("dpkg-packages-missing", "Debian-family image has no identifiable installed packages in its dpkg database.")

    def report(self):
        if not self.metadata:
            self.gap("metadata-missing", "No supported package metadata was found; inventory coverage cannot be established.")
        elif not self.packages:
            self.gap("packages-missing", "No identifiable packages were collected; empty output does not establish inventory coverage.")
        files = [{"path": relative, "sha256": digest(data), "kind": kind}
                 for relative, (kind, data) in sorted(self.metadata.items())]
        inputs = {"imageDigest": self.image_id} if self.role == "image" else {"metadataDigest": digest(canonical(files))}
        return {
            "schemaVersion": 1, "kind": "NoshInventoryCollection", "role": self.role,
            "collector": {"name": "nosh-inventory", "version": VERSION},
            "status": "incomplete" if self.gaps else "complete", "input": inputs,
            "coverage": "supported-package-metadata",
            "exclusions": list(SOURCE_EXCLUSIONS) + ["/.nosh-install.*", "**/.git", "**/node_modules", "**/.next", "**/__pycache__"] if self.role == "source" else [],
            "gaps": sorted(self.gaps, key=lambda item: (item["code"], item["message"])),
            "limitations": sorted(self.limitations), "metadataFiles": files,
            "counts": {"metadataFiles": len(files), "packages": len(self.packages)},
        }

    def spdx(self, report):
        packages = [value for _, value in sorted(self.packages.items())]
        return {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"nosh-{self.role}-package-metadata",
            "documentNamespace": f"https://notty.dev/inventory/{self.role}/{digest(canonical(report))[7:]}",
            "creationInfo": {"created": EPOCH, "creators": ["Tool: nosh-inventory-1"]},
            "annotations": [{"annotationType": "OTHER", "annotator": "Tool: nosh-inventory-1",
                             "annotationDate": EPOCH, "comment": ANNOTATION_PREFIX + canonical(report).decode("utf-8")}],
            "packages": packages,
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": package["SPDXID"]} for package in packages],
        }


def read_regular_file(path, directory_fd=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise CollectionError("metadata is not a bounded regular file")
        data = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) or len(data) != before.st_size:
            raise CollectionError("metadata changed during collection")
        return data


def collect_source(root, inventory):
    def walk(directory_fd, prefix, depth):
        if depth > MAX_DEPTH:
            raise CollectionError("source directory nesting exceeds its limit")
        try:
            before = os.fstat(directory_fd)
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            for entry in entries:
                relative = prefix + entry.name
                if source_excluded(relative):
                    continue
                normalized_path(relative)
                inventory.count()
                kind = metadata_kind(relative, "source")
                attributes = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(attributes.st_mode):
                    if kind:
                        inventory.gap("metadata-link", f"Required source metadata is a symlink: {relative}")
                    else:
                        inventory.limitations.add("Source symlinks are not followed.")
                elif stat.S_ISDIR(attributes.st_mode):
                    child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        walk(child_fd, relative + "/", depth + 1)
                    finally:
                        os.close(child_fd)
                elif kind:
                    try:
                        inventory.add_metadata(relative, kind, read_regular_file(entry.name, directory_fd))
                    except (OSError, CollectionError) as error:
                        inventory.gap("metadata-unreadable", f"{relative}: {error}")
            after = os.fstat(directory_fd)
            if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                inventory.gap("source-changed", f"Source directory changed during collection: {prefix or '.'}")
        except OSError as error:
            inventory.gap("source-unreadable", f"Cannot inspect {prefix or '.'}: {error.strerror}")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(root_fd, "", 0)
    finally:
        os.close(root_fd)


def collect_image(archive, inventory):
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    seen = set()
    release_links = []
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
            raise CollectionError("image archive is not a bounded regular file")
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for member in tar:
                inventory.count()
                relative = normalized_path(member.name)
                if not relative:
                    if member.isdir():
                        continue
                    raise CollectionError("empty archive member path")
                if relative in seen:
                    raise CollectionError(f"duplicate archive path: {relative}")
                seen.add(relative)
                kind = metadata_kind(relative, "image")
                if member.issym() or member.islnk():
                    if kind == "os-release":
                        # /etc/os-release commonly links to /usr/lib/os-release;
                        # the regular fallback is cataloged independently.
                        release_links.append((relative, member.linkname, member.issym()))
                    elif kind:
                        inventory.gap("metadata-link", f"Required image metadata is a link: {relative}")
                    continue
                if member.isdir():
                    continue
                if not member.isfile() or member.issparse():
                    if kind:
                        inventory.gap("metadata-file-type", f"Unsupported metadata file type: {relative}")
                    continue
                if PurePosixPath(relative).name in {"node", "ollama", "antigravity", "agy"}:
                    inventory.limitations.add(f"Additional executable {relative}: package metadata coverage and executable version are not established.")
                if "/lib/dpkg/status.d/" in relative and PurePosixPath(relative).suffix in {".md5sums", ".list", ".conffiles", ".triggers"}:
                    continue
                if kind:
                    if member.size > MAX_FILE_BYTES:
                        raise CollectionError(f"metadata file exceeds its byte limit: {relative}")
                    contents = tar.extractfile(member)
                    if contents is None:
                        raise CollectionError(f"cannot read metadata: {relative}")
                    data = contents.read(MAX_FILE_BYTES + 1)
                    if len(data) != member.size:
                        raise CollectionError(f"truncated metadata file: {relative}")
                    inventory.add_metadata(relative, kind, data)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise CollectionError("image archive changed during collection")
    for relative, target, symbolic in release_links:
        fallback = "usr/lib/os-release" if relative == "etc/os-release" else "etc/os-release"
        relative_target = "../usr/lib/os-release" if relative == "etc/os-release" else "../../etc/os-release"
        allowed_targets = {"/" + fallback, relative_target} if symbolic else {fallback, "./" + fallback}
        if target in allowed_targets and fallback in inventory.metadata:
            inventory.limitations.add("OS release symlinks are not followed; the regular os-release fallback was inventoried.")
        else:
            inventory.gap("metadata-link", f"OS release metadata link has no supported regular fallback: {relative}")


def write_outputs(directory, inventory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid():
        raise CollectionError("output must be a caller-owned real directory")
    if info.st_mode & 0o022:
        raise CollectionError("output directory must not be writable by other users")
    report = inventory.report()
    sbom_bytes = canonical(inventory.spdx(report)) + b"\n"
    report["sbomDigest"] = digest(sbom_bytes)
    report_bytes = canonical(report) + b"\n"
    if max(len(sbom_bytes), len(report_bytes)) > MAX_OUTPUT_BYTES:
        raise CollectionError("inventory output exceeds its byte limit")
    paths = [directory / f"{inventory.role}.spdx.json", directory / f"{inventory.role}.collection.json"]
    written = []
    try:
        for output, content in zip(paths, (sbom_bytes, report_bytes)):
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            written.append(output)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for output in written:
            output.unlink()
        raise
    return {"role": inventory.role, "status": report["status"], "sbomPath": str(paths[0]),
            "collectionPath": str(paths[1]), "sbomDigest": report["sbomDigest"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="nosh-inventory 1")
    subparsers = parser.add_subparsers(dest="role", required=True)
    for role in ("source", "image"):
        command = subparsers.add_parser(role)
        command.add_argument("--input", required=True)
        command.add_argument("--output", required=True)
        if role == "image":
            command.add_argument("--image-id", required=True)
    options = parser.parse_args(argv)
    image_id = getattr(options, "image_id", None)
    if options.role == "image" and not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        parser.error("--image-id must be an exact sha256 image ID")
    inventory = Inventory(options.role, image_id)
    try:
        source = Path(options.input)
        if options.role == "source":
            if source.is_symlink() or not source.is_dir():
                raise CollectionError("source input must be a real directory")
            collect_source(source, inventory)
        else:
            collect_image(source, inventory)
    except (OSError, ValueError, tarfile.TarError, EOFError, RecursionError) as error:
        inventory.gap("collection-failed", str(error))
    try:
        inventory.parse()
    except (ValueError, TypeError, RecursionError) as error:
        inventory.gap("collection-failed", str(error))
    try:
        result = write_outputs(options.output, inventory)
    except (OSError, ValueError) as error:
        print(f"nosh-inventory: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
