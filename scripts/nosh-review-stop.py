#!/usr/bin/env python3
"""Stop only the review services recorded in a private session receipt."""

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


MAX_STATE_BYTES = 16 * 1024
MAX_DOCKER_BYTES = 4 * 1024 * 1024
HEX = re.compile(r"[a-f0-9]{64}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
PROFILE_KEYS = {
    "profile_id", "profile_evidence_digest", "review_composition_digest",
    "graph_digest", "graph_content_digest", "policy_tooling_image",
}
SERVICE_KEYS = {
    "profile_id", "profile_evidence_digest", "graph_digest", "network_id",
    "ui_container_id", "graph_container_id", "ui_host", "graph_host",
    "graph_url", "ui_image", "tooling_image",
}
NETWORK_KEYS = {
    "graph_content_digest", "network_subnet", "network_gateway", "network_config_digest",
    "docker_endpoint",
}
LABEL_PREFIX = "io.notty.policy-review."


class StopError(ValueError):
    pass


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StopError("Docker returned duplicate JSON fields")
        result[key] = value
    return result


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Session:
    def __init__(self, directory):
        self.path = Path(directory).absolute()
        if self.path != self.path.resolve(strict=True):
            raise StopError("session must be a canonical directory without symlinks")
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = os.fstat(self.fd)
        if self.identity.st_uid != os.geteuid() or stat.S_IMODE(self.identity.st_mode) != 0o700:
            os.close(self.fd)
            raise StopError("session must be caller-owned with mode 0700")
        self.receipts = {}

    def close(self):
        os.close(self.fd)

    def check_directory(self):
        info = self.path.lstat()
        if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != (
                self.identity.st_dev, self.identity.st_ino,
                self.identity.st_uid, self.identity.st_mode):
            raise StopError("session directory changed during teardown")
        if self.path != self.path.resolve(strict=True):
            raise StopError("session directory path changed during teardown")

    def read(self, name):
        self.check_directory()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or before.st_size > MAX_STATE_BYTES):
                raise StopError(f"{name} must be a bounded caller-owned, singly linked mode 0600 file")
            data = os.read(fd, MAX_STATE_BYTES + 1)
            if len(data) != before.st_size or len(data) > MAX_STATE_BYTES or fingerprint(before) != fingerprint(os.fstat(fd)):
                raise StopError(f"{name} changed or exceeded its limit")
            if fingerprint(before) != fingerprint(os.stat(name, dir_fd=self.fd, follow_symlinks=False)):
                raise StopError(f"{name} was replaced during reading")
            return before, data
        finally:
            os.close(fd)

    def load(self, name):
        info, data = self.read(name)
        self.receipts[name] = (fingerprint(info), data)
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise StopError(f"{name} is not UTF-8") from error
        if not text.endswith("\n"):
            raise StopError(f"{name} must contain newline-terminated fields")
        result = {}
        for line in text.split("\n")[:-1]:
            if not re.fullmatch(r"[a-z_]+=[\x21-\x7e]+", line):
                raise StopError(f"{name} contains an invalid field")
            key, value = line.split("=", 1)
            if key in result:
                raise StopError(f"{name} contains a duplicate field")
            result[key] = value
        return result

    def unchanged(self):
        for name, expected in self.receipts.items():
            info, data = self.read(name)
            if (fingerprint(info), data) != expected:
                raise StopError(f"{name} changed during teardown; saved state retained")

    def remove_receipt(self):
        self.unchanged()
        os.unlink("services.state", dir_fd=self.fd)
        os.fsync(self.fd)


def private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
        return any(address in network for network in PRIVATE_NETWORKS)
    except (ValueError, TypeError):
        return False


def validate_state(profile, services):
    if set(profile) != PROFILE_KEYS or set(services) not in (SERVICE_KEYS, SERVICE_KEYS | NETWORK_KEYS):
        raise StopError("session receipt fields do not match a supported schema")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", profile["profile_id"]):
        raise StopError("invalid profile identity")
    for key in PROFILE_KEYS - {"profile_id"}:
        if not DIGEST.fullmatch(profile[key]):
            raise StopError(f"invalid profile {key}")
    for key in ("profile_id", "profile_evidence_digest", "graph_digest"):
        if services[key] != profile[key]:
            raise StopError("service and profile receipts do not match")
    if services["tooling_image"] != profile["policy_tooling_image"]:
        raise StopError("service tooling image does not match the profile")
    for key in ("ui_image", "tooling_image"):
        if not DIGEST.fullmatch(services[key]):
            raise StopError(f"invalid service {key}")
    for key in ("network_id", "ui_container_id", "graph_container_id"):
        if not HEX.fullmatch(services[key]):
            raise StopError(f"invalid service {key}")
    if services["ui_container_id"] == services["graph_container_id"]:
        raise StopError("UI and graph must have distinct container identities")
    if (not private_ipv4(services["ui_host"]) or not private_ipv4(services["graph_host"])
            or services["ui_host"] == services["graph_host"]):
        raise StopError("invalid review service addresses")
    graph_url = urlsplit(services["graph_url"])
    if (graph_url.scheme != "http" or graph_url.hostname != services["graph_host"]
            or not graph_url.port or graph_url.netloc != f'{services["graph_host"]}:{graph_url.port}'
            or not re.fullmatch(r"/v1/graph/[a-f0-9]{64}", graph_url.path)
            or graph_url.query or graph_url.fragment):
        raise StopError("invalid graph URL binding")
    if "network_subnet" in services:
        if not re.fullmatch(r"unix:///[^\x00-\x20\x7f]+", services["docker_endpoint"]):
            raise StopError("saved Docker endpoint must be a local Unix socket")
        if (services["graph_content_digest"] != profile["graph_content_digest"]
                or not DIGEST.fullmatch(services["network_config_digest"])):
            raise StopError("invalid network configuration binding")
        subnet = ipaddress.IPv4Network(services["network_subnet"], strict=True)
        gateway = ipaddress.IPv4Address(services["network_gateway"])
        if (subnet.prefixlen != 29 or not any(subnet.subnet_of(network) for network in PRIVATE_NETWORKS)
                or gateway != subnet.network_address + 1
                or any(ipaddress.IPv4Address(services[key]) not in subnet for key in ("ui_host", "graph_host"))):
            raise StopError("invalid review subnet or gateway")


class Docker:
    def __init__(self, executable="docker", runner=subprocess.run, environment=None,
                 clock=time.monotonic, sleeper=time.sleep):
        self.executable = executable
        self.runner = runner
        self.environment = os.environ.copy() if environment is None else environment
        self.clock = clock
        self.sleeper = sleeper

    def command(self, *args):
        try:
            result = self.runner([self.executable, *args], capture_output=True, text=True,
                                 timeout=30, check=False, env=self.environment)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise StopError(f"Docker {args[0]} could not complete") from error
        if result.returncode != 0:
            raise StopError(f"Docker {' '.join(args[:2])} failed; saved state retained")
        if len(result.stdout.encode("utf-8")) > MAX_DOCKER_BYTES:
            raise StopError("Docker response exceeded its limit")
        return result.stdout

    def json(self, *args):
        try:
            return json.loads(self.command(*args), object_pairs_hook=unique_json)
        except json.JSONDecodeError as error:
            raise StopError("Docker returned invalid JSON") from error

    def require_local(self):
        # Docker context overrides DOCKER_HOST. Resolve it without contacting a daemon.
        context = self.environment.get("DOCKER_CONTEXT")
        endpoint = self.environment.get("DOCKER_HOST") if not context else None
        if not endpoint:
            args = ("context", "inspect", context) if context else ("context", "inspect")
            value = self.json(*args)
            try:
                if not isinstance(value, list) or len(value) != 1:
                    raise KeyError("context")
                endpoint = value[0]["Endpoints"]["docker"]["Host"]
            except (KeyError, TypeError) as error:
                raise StopError("could not establish the local Docker endpoint") from error
        if not isinstance(endpoint, str) or not re.fullmatch(r"unix:///[^\x00-\x20\x7f]+", endpoint):
            raise StopError("review teardown requires a local Unix-socket Docker endpoint")
        # Pin every subsequent command to the inspected endpoint, including with a context selected.
        self.environment = dict(self.environment)
        self.environment.pop("DOCKER_CONTEXT", None)
        self.environment["DOCKER_HOST"] = endpoint
        return endpoint

    def ids(self, kind):
        args = (kind, "ls", "--all", "--quiet", "--no-trunc") if kind == "container" else (
            kind, "ls", "--quiet", "--no-trunc")
        lines = self.command(*args).splitlines()
        if any(not HEX.fullmatch(line) for line in lines) or len(set(lines)) != len(lines):
            raise StopError("Docker returned invalid full object identities")
        return set(lines)

    def inspect(self, kind, object_id):
        value = self.json(kind, "inspect", object_id)
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise StopError("Docker inspect did not return exactly one object")
        return value[0]

    def wait_absent(self, kind, object_ids):
        deadline = self.clock() + 5
        while self.ids(kind).intersection(object_ids):
            if self.clock() >= deadline:
                raise StopError(f"review {kind} objects still exist after teardown; saved state retained")
            self.sleeper(0.1)


def expected_labels(profile, component):
    return {LABEL_PREFIX + key: value for key, value in {
        "managed": "true", "component": component, "profile": profile["profile_id"],
        "profile-evidence-digest": profile["profile_evidence_digest"],
        "graph-digest": profile["graph_digest"], "graph-content-digest": profile["graph_content_digest"],
    }.items()}


def verify_labels(actual, expected):
    if not isinstance(actual, dict) or any(actual.get(key) != value for key, value in expected.items()):
        raise StopError("review object ownership labels do not match the saved receipt")


def verify_container(value, profile, services, component):
    if (value.get("Id") != services[component + "_container_id"]
            or value.get("Image") != services["ui_image" if component == "ui" else "tooling_image"]):
        raise StopError("review container identity or image does not match the saved receipt")
    config = value.get("Config")
    verify_labels(config.get("Labels") if isinstance(config, dict) else None, expected_labels(profile, component))


def verify_network(value, profile, services, empty=False):
    if (value.get("Id") != services["network_id"] or value.get("Driver") != "bridge"
            or value.get("Internal") is not True):
        raise StopError("review network identity or isolation does not match the saved receipt")
    labels = expected_labels(profile, "network")
    if "network_config_digest" in services:
        if value.get("EnableIPv6") is not False:
            raise StopError("review network IPv6 configuration does not match the saved receipt")
        labels[LABEL_PREFIX + "network-config-digest"] = services["network_config_digest"]
        ipam = value.get("IPAM")
        configs = ipam.get("Config") if isinstance(ipam, dict) else None
        if (not isinstance(configs, list) or len(configs) != 1 or not isinstance(configs[0], dict)
                or configs[0].get("Subnet") != services["network_subnet"]
                or configs[0].get("Gateway") != services["network_gateway"]
                or configs[0].get("IPRange") or configs[0].get("AuxAddress")
                or configs[0].get("AuxiliaryAddresses")):
            raise StopError("review network IPAM does not match the saved receipt")
    verify_labels(value.get("Labels"), labels)
    containers = value.get("Containers")
    if not isinstance(containers, dict):
        raise StopError("review network attachment inventory is missing")
    allowed = set() if empty else {services["ui_container_id"], services["graph_container_id"]}
    if not set(containers).issubset(allowed):
        raise StopError("review network has unexpected attachments; no network removal performed")


def stop_review(session, docker):
    profile = session.load("profile.state")
    services = session.load("services.state")
    validate_state(profile, services)
    endpoint = docker.require_local()
    if "docker_endpoint" in services and services["docker_endpoint"] != endpoint:
        raise StopError("current Docker endpoint differs from the saved review endpoint")
    container_ids = docker.ids("container")
    network_ids = docker.ids("network")
    components = [component for component in ("graph", "ui")
                  if services[component + "_container_id"] in container_ids]
    if "docker_endpoint" not in services and not components and services["network_id"] not in network_ids:
        raise StopError("legacy receipt has no Docker endpoint binding and no present review objects; saved state retained")
    # Establish ownership of every present object before changing any of them.
    for component in components:
        verify_container(docker.inspect("container", services[component + "_container_id"]),
                         profile, services, component)
    if services["network_id"] in network_ids:
        verify_network(docker.inspect("network", services["network_id"]), profile, services)
    session.unchanged()
    for component in components:
        object_id = services[component + "_container_id"]
        session.unchanged()
        if object_id not in docker.ids("container"):
            continue
        verify_container(docker.inspect("container", object_id), profile, services, component)
        session.unchanged()
        docker.command("stop", "--time", "3", object_id)
    docker.wait_absent("container", {services["ui_container_id"], services["graph_container_id"]})
    if services["network_id"] in docker.ids("network"):
        session.unchanged()
        verify_network(docker.inspect("network", services["network_id"]), profile, services, empty=True)
        session.unchanged()
        docker.command("network", "rm", services["network_id"])
    docker.wait_absent("network", {services["network_id"]})
    if docker.ids("container").intersection({services["ui_container_id"], services["graph_container_id"]}):
        raise StopError("review objects remain after teardown; saved state retained")
    session.remove_receipt()
    return {"schemaVersion": 1, "status": "stopped", "session": str(session.path),
            "containersRemoved": True, "networkRemoved": True, "savedReviewPreserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True, help="private review session directory")
    parser.add_argument("--docker-bin", default="docker", help="Docker CLI executable")
    args = parser.parse_args()
    session = None
    try:
        session = Session(args.session)
        print(json.dumps(stop_review(session, Docker(args.docker_bin))))
        return 0
    except (StopError, OSError, ValueError) as error:
        print(f"nosh-review-stop: {error}", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    sys.exit(main())
