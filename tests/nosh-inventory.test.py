#!/usr/bin/env python3
"""Offline collector tests. Fixtures are original, not copied package contents."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "nosh-inventory.py"
SPEC = importlib.util.spec_from_file_location("nosh_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)
IMAGE = "sha256:" + "a" * 64


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, value):
        file = self.root / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return file

    def source(self):
        result = inventory.Inventory("source")
        inventory.collect_source(self.root, result)
        result.parse()
        return result

    def archive(self, entries):
        destination = self.root / "image.tar"
        with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as output:
            for name, content, *extra in entries:
                info = tarfile.TarInfo(name)
                if extra:
                    info.type, info.linkname = extra
                    output.addfile(info)
                else:
                    info.size = len(content)
                    output.addfile(info, io.BytesIO(content))
        return destination

    def image(self, entries):
        result = inventory.Inventory("image", IMAGE)
        inventory.collect_image(self.archive(entries), result)
        result.parse()
        return result

    def annotations(self, result):
        return [(package, json.loads(package["annotations"][0]["comment"])) for package in result.packages.values()]

    def test_source_npm_v3_scoped_alias_dev_and_root(self):
        self.write("package.json", {"name": "project", "version": "1.0.0", "dependencies": {"alias": "1.0.0"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"name": "project", "version": "1.0.0"},
            "node_modules/alias": {"name": "@scope/real", "version": "2.3.4"},
            "node_modules/dev-tool": {"version": "4.5.6", "dev": True},
        }})
        result = self.source()
        self.assertEqual(result.report()["status"], "complete")
        package = next(p for p in result.packages.values() if p["name"] == "@scope/real")
        self.assertEqual(package["externalRefs"][0]["referenceLocator"], "pkg:npm/%40scope/real@2.3.4")
        dev = next(a for p, a in self.annotations(result) if p["name"] == "dev-tool")
        self.assertTrue(dev["development"])
        self.assertEqual(dev["evidence"], "declared")

    def test_npm_v1_nested_scoped_alias(self):
        self.write("npm-shrinkwrap.json", {"lockfileVersion": 1, "dependencies": {
            "first": {"version": "1.0.0", "dev": True, "dependencies": {
                "alias": {"version": "npm:@vendor/canonical@2.0.0"},
            }},
        }})
        result = self.source()
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual({p["name"] for p in result.packages.values()}, {"first", "@vendor/canonical"})

    def test_shrinkwrap_precedes_package_lock_and_v2_workspace_links(self):
        self.write("package-lock.json", {"lockfileVersion": 999})
        self.write("npm-shrinkwrap.json", {"lockfileVersion": 2, "packages": {
            "packages/one": {"name": "one", "version": "1.0.0"},
            "node_modules/one": {"resolved": "packages/one", "link": True},
        }})
        result = self.source()
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual(len(result.packages), 1)

    def test_missing_lock_and_unsupported_ecosystem_block(self):
        self.write("package.json", {"name": "app", "version": "1", "dependencies": {"x": "*"}})
        self.write("Cargo.lock", b"version = 3\n")
        result = self.source().report()
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue({"missing-npm-lock", "unsupported-lockfile"}.issubset({gap["code"] for gap in result["gaps"]}))

    def test_private_source_project_can_declare_an_unknown_version(self):
        self.write("package.json", {"name": "private-workspace", "private": True})
        result = self.source()
        self.assertEqual(result.report()["status"], "complete")
        package = next(iter(result.packages.values()))
        self.assertNotIn("versionInfo", package)
        self.assertTrue(any("version" in value and "unknown" in value for value in result.limitations))

    def test_unsupported_installed_package_database_blocks_coverage(self):
        result = self.image([
            ("lib/apk/db/installed", b"P:package\nV:1\n"),
            ("app/package.json", b'{"name":"app","version":"1"}'),
        ])
        self.assertEqual(result.report()["status"], "incomplete")
        self.assertTrue(any(gap["code"] == "unsupported-package-database" for gap in result.gaps))

    def test_source_excludes_recon_cache_and_node_modules(self):
        self.write("package.json", {"name": "app", "version": "1"})
        for prefix in ("tmp/syft", "cache/work", ".git", "node_modules/something", "nested/node_modules/x", "agents/runs/one"):
            self.write(prefix + "/package.json", b"invalid")
            self.write(prefix + "/Cargo.lock", b"unsupported")
        result = self.source().report()
        self.assertEqual(result["status"], "complete")
        self.assertEqual([f["path"] for f in result["metadataFiles"]], ["package.json"])

    def test_source_excludes_root_installer_staging_but_not_nested_project(self):
        self.write("package.json", {"name": "app", "version": "1"})
        self.write(".nosh-install.abcdef/package.json", b"generated installer metadata")
        self.write(".nosh-install.abcdef/Cargo.lock", b"not source")
        self.write("nested/.nosh-install.real-project/package.json", {"name": "nested", "version": "2"})
        report = self.source().report()
        self.assertEqual(report["status"], "complete")
        self.assertEqual([file["path"] for file in report["metadataFiles"]],
                         ["nested/.nosh-install.real-project/package.json", "package.json"])
        self.assertIn("/.nosh-install.*", report["exclusions"])

    def test_metadata_scripts_are_never_executed(self):
        marker = self.root / "executed"
        self.write("package.json", {"name": "app", "version": "1", "scripts": {"prepare": f"touch {marker}"}})
        self.write("pyproject.toml", b'[project]\nname="copied"\nversion="2.0"\n[build-system]\nrequires=["evil"]\nbuild-backend="evil"\n')
        self.write("evil.py", b"raise RuntimeError('must not import')\n")
        self.assertEqual(self.source().report()["status"], "complete")
        self.assertFalse(marker.exists())

    def test_image_npm_installed_and_copied_project_are_distinct(self):
        result = self.image([
            ("app/package.json", b'{"name":"app","version":"1"}'),
            ("usr/local/lib/node_modules/@scope/tool/package.json", b'{"name":"@scope/tool","version":"2"}'),
            ("app/node_modules/x/package.json", b'{"name":"x","version":"3"}'),
            ("app/node_modules/x/test/package.json", b"malformed fixture should not be a package root"),
            ("app/package-lock.json", b"a source lockfile is not installed evidence"),
        ])
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual({p["name"]: a["evidence"] for p, a in self.annotations(result)},
                         {"app": "copied", "@scope/tool": "installed", "x": "installed"})

    def test_duplicate_package_identity_preserves_multiple_locations(self):
        result = self.image([
            ("app/node_modules/x/package.json", b'{"name":"x","version":"1"}'),
            ("usr/local/lib/node_modules/x/package.json", b'{"name":"x","version":"1"}'),
        ])
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual(len(result.packages), 1)
        package = next(iter(result.packages.values()))
        self.assertEqual({json.loads(annotation["comment"])["path"] for annotation in package["annotations"]},
                         {"app/node_modules/x/package.json", "usr/local/lib/node_modules/x/package.json"})

    def test_dpkg_status_continuations_removed_and_no_final_newline(self):
        status_data = (b"Package: installed\nStatus: install ok installed\nArchitecture: amd64\n"
                       b"Source: upstream (1.2)\nDescription: line one\n line two\nVersion: 1.2-3\n\n"
                       b"Package: removed\nStatus: deinstall ok config-files\nVersion: 3\n\n"
                       b"Package: last\nStatus: install ok installed\nVersion: 4.0")
        result = self.image([("var/lib/dpkg/status", status_data), ("etc/os-release", b'ID=debian\n')])
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual({p["name"] for p in result.packages.values()}, {"installed", "last"})
        installed = next(p for p in result.packages.values() if p["name"] == "installed")
        self.assertEqual(installed["externalRefs"][0]["referenceLocator"], "pkg:deb/debian/installed@1.2-3?arch=amd64")

    def test_dpkg_status_d_skips_auxiliary_files(self):
        result = self.image([
            ("var/lib/dpkg/status.d/pkg", b"Package: pkg\nVersion: 1.0\nArchitecture: all\n"),
            ("var/lib/dpkg/status.d/pkg.md5sums", b"1234 usr/lib/x\n"),
        ])
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual(len(result.packages), 1)

    def test_debian_family_missing_database_blocks_even_with_installed_npm(self):
        for release in (b"ID=debian\n", b"ID=ubuntu\n", b'ID=derivative\nID_LIKE="ubuntu debian"\n'):
            with self.subTest(release=release):
                result = self.image([
                    ("usr/lib/os-release", release),
                    ("app/node_modules/x/package.json", b'{"name":"x","version":"1"}'),
                ])
                self.assertEqual(result.report()["status"], "incomplete")
                self.assertTrue(any(gap["code"] == "dpkg-database-missing" for gap in result.gaps))

    def test_debian_family_empty_database_does_not_establish_package_coverage(self):
        result = self.image([
            ("usr/lib/os-release", b"ID=debian\n"),
            ("var/lib/dpkg/status", b""),
            ("app/node_modules/x/package.json", b'{"name":"x","version":"1"}'),
        ])
        self.assertEqual(result.report()["status"], "incomplete")
        self.assertTrue(any(gap["code"] == "dpkg-packages-missing" for gap in result.gaps))

    def test_distro_release_symlink_uses_regular_fallback(self):
        result = self.image([
            ("etc/os-release", b"", tarfile.SYMTYPE, "../usr/lib/os-release"),
            ("usr/lib/os-release", b'ID=debian\n'),
            ("var/lib/dpkg/status", b"Package: pkg\nStatus: install ok installed\nVersion: 1\n"),
        ])
        self.assertEqual(result.report()["status"], "complete")
        package = next(iter(result.packages.values()))
        self.assertEqual(package["externalRefs"][0]["referenceLocator"], "pkg:deb/debian/pkg@1")

    def test_arbitrary_distro_release_link_or_missing_fallback_blocks(self):
        for target in ("/private/file", "../usr/lib/os-release"):
            result = self.image([
                ("etc/os-release", b"", tarfile.SYMTYPE, target),
                ("var/lib/dpkg/status", b"Package: pkg\nStatus: install ok installed\nVersion: 1\n"),
            ])
            self.assertEqual(result.report()["status"], "incomplete")
            self.assertTrue(any(gap["code"] == "metadata-link" for gap in result.gaps))

    def test_python_installed_folded_repeated_fields_and_standalone_egg(self):
        result = self.image([
            ("opt/venv/lib/python3.11/site-packages/some.dist-info/METADATA",
             b"Metadata-Version: 2.1\nName: Some_Package\nVersion: 1.2.3\nRequires-Dist: one\nRequires-Dist: two;\n python_version>='3'\n\nlong description: irrelevant\n"),
            ("usr/lib/python3/dist-packages/legacy.egg-info", b"Name: Legacy\nVersion: 4"),
            ("opt/durdraw/pyproject.toml", b'[project]\nname="durdraw"\nversion="0.29.0"\n'),
        ])
        self.assertEqual(result.report()["status"], "complete")
        self.assertEqual({p["name"]: a["evidence"] for p, a in self.annotations(result)},
                         {"some-package": "installed", "legacy": "installed", "durdraw": "copied"})

    def test_python_long_field_duplicate_identity_and_dynamic_version_block(self):
        result = self.image([
            ("x.dist-info/METADATA", b"Name: x\nVersion: 1\nDescription: " + b"a" * 65537),
            ("y.dist-info/METADATA", b"Name: x\nName: y\nVersion: 1\n"),
            ("app/pyproject.toml", b'[project]\nname="app"\ndynamic=["version"]\n'),
        ])
        self.assertEqual(result.report()["status"], "incomplete")
        self.assertEqual(len([gap for gap in result.gaps if gap["code"] == "metadata-invalid"]), 3)

    def test_malformed_json_duplicate_fields_and_unknown_lock_version_block(self):
        self.write("package.json", b'{"name":"one","name":"two","version":"1"}')
        self.write("package-lock.json", {"lockfileVersion": 99})
        result = self.source().report()
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any("duplicate JSON" in gap["message"] for gap in result["gaps"]))

    def test_unsafe_archive_names_and_duplicates_rejected(self):
        for name in ("../package.json", "/app/package.json", "a/../../package.json", "C:/package.json", "app\\package.json"):
            with self.subTest(name=name), self.assertRaises(inventory.CollectionError):
                self.image([(name, b"{}")])
        with self.assertRaises(inventory.CollectionError):
            self.image([("app/package.json", b"{}"), ("./app/package.json", b"{}")])

    def test_linked_metadata_is_incomplete_and_not_followed(self):
        for link_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(link_type=link_type):
                result = self.image([
                    ("app/package.json", b"", link_type, "/outside/secret"),
                    ("safe/package.json", b'{"name":"safe","version":"1"}'),
                ])
                self.assertEqual(result.report()["status"], "incomplete")
                self.assertTrue(any(gap["code"] == "metadata-link" for gap in result.gaps))
                self.assertEqual({p["name"] for p in result.packages.values()}, {"safe"})

    def test_source_metadata_symlink_and_fifo_are_not_read(self):
        outside = self.root / "not-json"
        outside.write_text("secret")
        (self.root / "package.json").symlink_to(outside)
        os.mkfifo(self.root / "package-lock.json")
        result = self.source().report()
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue({"metadata-link", "metadata-unreadable"}.issubset({gap["code"] for gap in result["gaps"]}))

    def test_truncated_archive_fails_instead_of_completing(self):
        archive = self.archive([("app/package.json", b"x" * 4096)])
        archive.write_bytes(archive.read_bytes()[:512 + 100])
        with self.assertRaises((tarfile.ReadError, inventory.CollectionError)):
            inventory.collect_image(archive, inventory.Inventory("image", IMAGE))

    def test_file_aggregate_package_and_member_bounds(self):
        for constant, limit in (("MAX_FILE_BYTES", 8), ("MAX_METADATA_BYTES", 8), ("MAX_MEMBERS", 0)):
            with self.subTest(constant=constant), mock.patch.object(inventory, constant, limit):
                with self.assertRaises(inventory.CollectionError):
                    self.image([("app/package.json", b'{"name":"app","version":"1"}')])
        with mock.patch.object(inventory, "MAX_PACKAGES", 0):
            result = self.image([("app/package.json", b'{"name":"app","version":"1"}')])
            self.assertEqual(result.report()["status"], "incomplete")

    def test_additional_native_components_are_limitations_not_fabricated_packages(self):
        result = self.image([
            ("usr/local/bin/node", b"not executed"),
            ("usr/local/bin/ollama", b"not executed"),
            ("app/package.json", b'{"name":"app","version":"1"}'),
        ])
        report = result.report()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(result.packages), 1)
        self.assertTrue(any("usr/local/bin/node" in value for value in report["limitations"]))

    def test_empty_inventory_never_establishes_coverage(self):
        self.assertEqual(self.source().report()["status"], "incomplete")
        self.write("package.json", {"type": "module"})
        self.assertEqual(self.source().report()["status"], "incomplete")

    def test_spdx_embedded_report_hashes_determinism_and_private_outputs(self):
        self.write("package.json", {"name": "app", "version": "1"})
        result = self.source()
        first_output = inventory.write_outputs(self.root / "out-one", result)
        second_output = inventory.write_outputs(self.root / "out-two", result)
        sbom_data = Path(first_output["sbomPath"]).read_bytes()
        self.assertEqual(sbom_data, Path(second_output["sbomPath"]).read_bytes())
        sidecar = json.loads(Path(first_output["collectionPath"]).read_bytes())
        self.assertEqual(sidecar["sbomDigest"], "sha256:" + hashlib.sha256(sbom_data).hexdigest())
        spdx = json.loads(sbom_data)
        embedded = json.loads(spdx["annotations"][0]["comment"][len(inventory.ANNOTATION_PREFIX):])
        self.assertNotIn("sbomDigest", embedded)
        self.assertEqual({key: value for key, value in sidecar.items() if key != "sbomDigest"}, embedded)
        self.assertEqual(embedded["metadataFiles"][0]["sha256"], inventory.digest((self.root / "package.json").read_bytes()))
        self.assertEqual(embedded["input"]["metadataDigest"], inventory.digest(inventory.canonical(embedded["metadataFiles"])))
        self.assertEqual(stat.S_IMODE(Path(first_output["sbomPath"]).stat().st_mode), 0o600)

    def test_outputs_are_exclusive_and_symlink_directory_rejected(self):
        self.write("package.json", {"name": "app", "version": "1"})
        result = self.source()
        output = self.root / "output"
        inventory.write_outputs(output, result)
        original = (output / "source.spdx.json").read_bytes()
        with self.assertRaises(FileExistsError):
            inventory.write_outputs(output, result)
        self.assertEqual((output / "source.spdx.json").read_bytes(), original)
        linked = self.root / "linked"
        linked.symlink_to(output, target_is_directory=True)
        with self.assertRaises(inventory.CollectionError):
            inventory.write_outputs(linked, result)

    def test_cli_complete_and_incomplete_exit_status(self):
        self.write("source/package.json", {"name": "app", "version": "1"})
        complete = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "source", "--input",
                                   str(self.root / "source"), "--output", str(self.root / "out")],
                                  capture_output=True, text=True)
        self.assertEqual(complete.returncode, 0, complete.stderr)
        self.assertEqual(json.loads(complete.stdout)["status"], "complete")
        (self.root / "empty").mkdir()
        incomplete = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "source", "--input",
                                     str(self.root / "empty"), "--output", str(self.root / "out-empty")],
                                    capture_output=True, text=True)
        self.assertEqual(incomplete.returncode, 2, incomplete.stderr)
        self.assertEqual(json.loads(incomplete.stdout)["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
