#!/usr/bin/env python3
"""Exercise receipt-bound teardown without contacting a Docker daemon."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "nosh-review-stop.py"
SPEC = importlib.util.spec_from_file_location("review_stop", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(character):
    return "sha256:" + character * 64


class DockerRunner:
    def __init__(self, profile, services):
        self.calls = []
        self.mutations = []
        self.fail = None
        self.hook = None
        self.auto_remove = True
        self.context_endpoint = "unix:///var/run/docker.sock"
        self.containers = {}
        for component in ("ui", "graph"):
            object_id = services[component + "_container_id"]
            self.containers[object_id] = {
                "Id": object_id,
                "Image": services["ui_image" if component == "ui" else "tooling_image"],
                "Config": {"Labels": MODULE.expected_labels(profile, component)},
            }
        labels = MODULE.expected_labels(profile, "network")
        if "network_config_digest" in services:
            labels[MODULE.LABEL_PREFIX + "network-config-digest"] = services["network_config_digest"]
        self.networks = {services["network_id"]: {
            "Id": services["network_id"], "Driver": "bridge", "Internal": True,
            "EnableIPv6": False,
            "Labels": labels, "Containers": {key: {} for key in self.containers},
            "IPAM": {"Config": [{"Subnet": services.get("network_subnet", "172.29.7.0/24"),
                                   "Gateway": services.get("network_gateway", "172.29.7.1")}]},
        }}

    def __call__(self, argv, **kwargs):
        args = argv[1:]
        self.calls.append(args)
        assert kwargs["timeout"] == 30
        if self.hook:
            self.hook(args)
        if self.fail and self.fail(args):
            return subprocess.CompletedProcess(argv, 1, "", "test failure")
        if args[:2] == ["context", "inspect"]:
            result = json.dumps([{"Endpoints": {"docker": {"Host": self.context_endpoint}}}])
        elif args == ["container", "ls", "--all", "--quiet", "--no-trunc"]:
            result = "".join(key + "\n" for key in self.containers)
        elif args == ["network", "ls", "--quiet", "--no-trunc"]:
            result = "".join(key + "\n" for key in self.networks)
        elif args[:2] in (["container", "inspect"], ["network", "inspect"]):
            objects = self.containers if args[0] == "container" else self.networks
            if args[2] not in objects:
                return subprocess.CompletedProcess(argv, 1, "", "not found")
            result = json.dumps([objects[args[2]]])
        elif args[:3] == ["stop", "--time", "3"]:
            self.mutations.append(args)
            if self.auto_remove:
                self.containers.pop(args[3])
                for network in self.networks.values():
                    network["Containers"].pop(args[3], None)
            result = args[3] + "\n"
        elif args[:2] == ["network", "rm"]:
            self.mutations.append(args)
            if self.networks[args[2]]["Containers"]:
                return subprocess.CompletedProcess(argv, 1, "", "active endpoints")
            self.networks.pop(args[2])
            result = args[2] + "\n"
        else:
            raise AssertionError(f"unexpected Docker command: {args}")
        return subprocess.CompletedProcess(argv, 0, result, "")


class ReviewStopTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nosh-review-stop-test-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "session"
        self.path.mkdir(mode=0o700)
        self.profile = {
            "profile_id": "7b18476c-e380-45e3-b84f-e3466ae6d898",
            "profile_evidence_digest": digest("a"), "review_composition_digest": digest("b"),
            "graph_digest": digest("c"), "graph_content_digest": digest("d"),
            "policy_tooling_image": digest("e"),
        }
        self.services = {
            "profile_id": self.profile["profile_id"], "profile_evidence_digest": digest("a"),
            "graph_digest": digest("c"), "network_id": "1" * 64,
            "ui_container_id": "2" * 64, "graph_container_id": "3" * 64,
            "ui_host": "10.231.0.2", "graph_host": "10.231.0.3",
            "graph_url": "http://10.231.0.3:3000/v1/graph/" + "4" * 64,
            "ui_image": digest("f"), "tooling_image": digest("e"),
            "graph_content_digest": digest("d"), "network_subnet": "10.231.0.0/29",
            "network_gateway": "10.231.0.1", "network_config_digest": digest("5"),
            "docker_endpoint": "unix:///var/run/docker.sock",
        }
        self.write_receipts()
        (self.path / "decisions").mkdir(mode=0o700)
        (self.path / "decisions" / "decisions.json").write_text('{"saved": true}')
        (self.path / "bundle").mkdir(mode=0o700)
        (self.path / "runtime-attestation.json").write_text("preserve")
        self.runner = DockerRunner(self.profile, self.services)

    def write_receipts(self):
        for name, value in (("profile.state", self.profile), ("services.state", self.services)):
            target = self.path / name
            target.write_text("".join(f"{key}={item}\n" for key, item in value.items()))
            target.chmod(0o600)

    def run_stop(self, environment=None):
        session = MODULE.Session(str(self.path))
        ticks = [0.0]
        def sleep(seconds):
            ticks[0] += seconds
        try:
            return MODULE.stop_review(session, MODULE.Docker(
                "fake-docker", self.runner,
                {"DOCKER_HOST": "unix:///var/run/docker.sock"} if environment is None else environment,
                clock=lambda: ticks[0], sleeper=sleep,
            ))
        finally:
            session.close()

    def assert_refused(self):
        with self.assertRaises((MODULE.StopError, OSError, ValueError)):
            self.run_stop()
        self.assertEqual(self.runner.mutations, [])
        self.assertTrue((self.path / "services.state").exists())

    def test_new_receipt_removes_exact_services_network_and_preserves_saved_review(self):
        foreign = "6" * 64
        self.runner.containers[foreign] = {"Id": foreign}
        result = self.run_stop()
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(self.runner.mutations, [
            ["stop", "--time", "3", "3" * 64], ["stop", "--time", "3", "2" * 64],
            ["network", "rm", "1" * 64],
        ])
        self.assertEqual(set(self.runner.containers), {foreign})
        self.assertFalse((self.path / "services.state").exists())
        self.assertEqual((self.path / "decisions" / "decisions.json").read_text(), '{"saved": true}')
        self.assertTrue((self.path / "profile.state").exists())
        self.assertTrue((self.path / "bundle").is_dir())
        self.assertEqual((self.path / "runtime-attestation.json").read_text(), "preserve")

    def test_legacy_receipt_uses_content_digest_from_profile(self):
        for key in MODULE.NETWORK_KEYS:
            self.services.pop(key)
        self.write_receipts()
        self.runner = DockerRunner(self.profile, self.services)
        self.runner.networks["1" * 64]["EnableIPv6"] = True
        self.assertEqual(self.run_stop()["status"], "stopped")

    def test_all_objects_already_absent_removes_receipt_without_mutation(self):
        self.runner.containers.clear()
        self.runner.networks.clear()
        self.run_stop()
        self.assertEqual(self.runner.mutations, [])
        self.assertFalse((self.path / "services.state").exists())

    def test_legacy_all_absent_cannot_prove_current_daemon_and_preserves_receipt(self):
        for key in MODULE.NETWORK_KEYS:
            self.services.pop(key)
        self.write_receipts()
        self.runner.containers.clear()
        self.runner.networks.clear()
        self.assert_refused()

    def test_new_receipt_requires_current_daemon_endpoint_match_before_inspection(self):
        self.services["docker_endpoint"] = "unix:///run/another-docker.sock"
        self.write_receipts()
        self.assert_refused()
        self.assertEqual(self.runner.calls, [])

    def test_container_image_mismatch_blocks_all_mutations(self):
        self.runner.containers["2" * 64]["Image"] = digest("0")
        self.assert_refused()

    def test_every_identity_label_is_checked_before_any_mutation(self):
        for component, container_id in (("ui", "2" * 64), ("graph", "3" * 64)):
            for key in MODULE.expected_labels(self.profile, component):
                with self.subTest(component=component, label=key):
                    self.runner = DockerRunner(self.profile, self.services)
                    self.runner.containers[container_id]["Config"]["Labels"][key] = "foreign"
                    self.assert_refused()

    def test_foreign_network_endpoint_blocks_stopping_known_containers(self):
        self.runner.networks["1" * 64]["Containers"]["6" * 64] = {}
        self.assert_refused()

    def test_new_network_requires_exact_ipam_isolation_and_config_label(self):
        for mutate in (
            lambda network: network.update(Internal=False),
            lambda network: network.update(EnableIPv6=True),
            lambda network: network.pop("EnableIPv6"),
            lambda network: network.update(Driver="overlay"),
            lambda network: network.update(Id="7" * 64),
            lambda network: network["IPAM"]["Config"][0].update(Subnet="10.0.0.0/8"),
            lambda network: network["IPAM"]["Config"][0].update(Gateway="10.231.0.4"),
            lambda network: network["IPAM"]["Config"][0].update(AuxAddress={"extra": "10.231.0.4"}),
            lambda network: network["IPAM"]["Config"][0].update(AuxiliaryAddresses={"extra": "10.231.0.4"}),
            lambda network: network["IPAM"]["Config"].append({"Subnet": "fd00::/64"}),
            lambda network: network["Labels"].update({MODULE.LABEL_PREFIX + "network-config-digest": digest("0")}),
        ):
            with self.subTest(mutation=mutate):
                self.runner = DockerRunner(self.profile, self.services)
                mutate(self.runner.networks["1" * 64])
                self.assert_refused()

    def test_invalid_receipt_fields_are_rejected_before_docker_calls(self):
        original = copy.deepcopy(self.services)
        for key, value in (("ui_container_id", "short"), ("tooling_image", digest("0")),
                           ("unexpected", "field"), ("network_gateway", "192.168.1.1"),
                           ("network_gateway", "10.231.0.4"), ("network_subnet", "10.231.0.0/24"),
                           ("graph_content_digest", digest("0")), ("ui_host", "8.8.8.8"),
                           ("graph_url", "http://10.231.0.3:3000/v1/graph/" + "4" * 64 + "?leak=true")):
            with self.subTest(key=key):
                self.services = dict(original)
                self.services[key] = value
                self.write_receipts()
                self.assert_refused()
                self.assertEqual(self.runner.calls, [])

    def test_duplicate_crlf_and_oversized_receipts_are_rejected(self):
        receipt = self.path / "services.state"
        original = receipt.read_text()
        for data in (original + "ui_host=10.231.0.2\n", original.replace("\n", "\r\n"), "a" * 20000):
            with self.subTest(length=len(data)):
                receipt.write_text(data)
                self.assert_refused()

    def test_untrusted_file_modes_and_hardlinks_are_rejected(self):
        receipt = self.path / "services.state"
        receipt.chmod(0o644)
        self.assert_refused()
        receipt.chmod(0o600)
        os.link(receipt, self.path / "copy.state")
        self.assert_refused()

    def test_symlinked_receipt_or_directory_is_rejected(self):
        receipt = self.path / "services.state"
        receipt.rename(self.path / "original.state")
        receipt.symlink_to("original.state")
        self.assert_refused()
        link = self.path.parent / "alias"
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(MODULE.StopError):
            MODULE.Session(str(link))

    def test_untrusted_directory_is_rejected(self):
        self.path.chmod(0o755)
        with self.assertRaises(MODULE.StopError):
            MODULE.Session(str(self.path))

    def test_listing_or_inspection_failure_is_not_treated_as_absence(self):
        for prefix in (["container", "ls"], ["network", "ls"], ["container", "inspect"], ["network", "inspect"]):
            with self.subTest(prefix=prefix):
                self.runner.fail = lambda args: args[:2] == prefix
                self.assert_refused()

    def test_remote_docker_endpoint_is_rejected_without_daemon_access(self):
        for environment in ({"DOCKER_HOST": "ssh://host"}, {"DOCKER_HOST": "tcp://host:2376"}):
            with self.subTest(environment=environment):
                with self.assertRaises(MODULE.StopError):
                    self.run_stop(environment)
                self.assertEqual(self.runner.calls, [])

    def test_context_endpoint_is_resolved_and_pinned(self):
        self.run_stop({"DOCKER_CONTEXT": "local-test", "DOCKER_HOST": "tcp://ignored:2376"})
        self.assertEqual(self.runner.calls[0], ["context", "inspect", "local-test"])

    def test_remote_context_is_rejected_even_with_local_docker_host(self):
        self.runner.context_endpoint = "ssh://host"
        with self.assertRaises(MODULE.StopError):
            self.run_stop({"DOCKER_CONTEXT": "remote", "DOCKER_HOST": "unix:///var/run/docker.sock"})
        self.assertEqual(self.runner.calls, [["context", "inspect", "remote"]])

    def test_partial_stop_failure_retains_receipt_for_safe_retry(self):
        self.runner.fail = lambda args: args == ["stop", "--time", "3", "2" * 64]
        with self.assertRaises(MODULE.StopError):
            self.run_stop()
        self.assertTrue((self.path / "services.state").exists())
        self.assertNotIn("3" * 64, self.runner.containers)
        self.assertIn("2" * 64, self.runner.containers)
        self.runner.fail = None
        self.assertEqual(self.run_stop()["status"], "stopped")

    def test_network_remove_failure_preserves_receipt(self):
        self.runner.fail = lambda args: args[:2] == ["network", "rm"]
        with self.assertRaises(MODULE.StopError):
            self.run_stop()
        self.assertTrue((self.path / "services.state").exists())
        self.assertEqual(self.runner.containers, {})

    def test_container_remaining_after_stop_preserves_receipt_and_network(self):
        self.runner.auto_remove = False
        with self.assertRaises(MODULE.StopError):
            self.run_stop()
        self.assertTrue((self.path / "services.state").exists())
        self.assertTrue(self.runner.networks)
        self.assertFalse(any(args[:2] == ["network", "rm"] for args in self.runner.mutations))

    def test_attachment_added_during_stop_prevents_network_removal(self):
        def hook(args):
            if args == ["stop", "--time", "3", "2" * 64]:
                self.runner.networks["1" * 64]["Containers"]["6" * 64] = {}
        self.runner.hook = hook
        with self.assertRaises(MODULE.StopError):
            self.run_stop()
        self.assertTrue((self.path / "services.state").exists())
        self.assertFalse(any(args[:2] == ["network", "rm"] for args in self.runner.mutations))

    def test_receipt_replacement_after_docker_cleanup_is_preserved(self):
        def hook(args):
            if args[:2] == ["network", "rm"]:
                receipt = self.path / "services.state"
                previous = receipt.read_bytes()
                receipt.unlink()
                receipt.write_bytes(previous)
                receipt.chmod(0o600)
        self.runner.hook = hook
        with self.assertRaises(MODULE.StopError):
            self.run_stop()
        self.assertTrue((self.path / "services.state").exists())

    def test_receipt_change_before_first_mutation_prevents_all_changes(self):
        def hook(args):
            if args[:2] == ["network", "inspect"]:
                (self.path / "services.state").write_text("replacement=true\n")
        self.runner.hook = hook
        self.assert_refused()

    def test_receipt_change_during_container_reinspection_prevents_stop(self):
        count = [0]
        def hook(args):
            if args == ["container", "inspect", "3" * 64]:
                count[0] += 1
                if count[0] == 2:
                    (self.path / "services.state").write_text("replacement=true\n")
        self.runner.hook = hook
        self.assert_refused()

    def test_container_autoremove_delay_is_bounded_and_can_complete(self):
        count = [0]
        self.runner.auto_remove = False
        def hook(args):
            if args[:2] == ["container", "ls"] and len(self.runner.mutations) == 2:
                count[0] += 1
                if count[0] == 3:
                    self.runner.containers.clear()
                    self.runner.networks["1" * 64]["Containers"].clear()
        self.runner.hook = hook
        self.assertEqual(self.run_stop()["status"], "stopped")
        self.assertGreaterEqual(count[0], 3)


if __name__ == "__main__":
    unittest.main()
