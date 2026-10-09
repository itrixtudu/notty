#!/usr/bin/env python3
"""Pure state and queue model for the host-side Nosh initialization TUI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import getpass
import json
import os
import re
from typing import Any, Iterable


DERIVED_FROM_BASE = re.compile(
    r"(?ms)^\s*ARG\s+NOSH_IMAGE(?:\s*=.*)?$.*?^\s*FROM\s+\$\{NOSH_IMAGE\}(?:\s|$)"
)
WORKLOAD_IMAGE_NAME = re.compile(r"nosh(?:-[a-z0-9][a-z0-9_.-]*)?\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
BUILD_CAPTURE_DESCRIPTION = (
    "See which network destinations dependencies and install scripts contact during this build. "
    "Review unexpected connections before promoting the image through CI/CD.\n\n"
    "Shai-Hulud-style supply-chain attacks can hide secret-stealing code in install scripts. "
    "Capture provides evidence to investigate and help with malware detection or blocking decisions. "
    "It does not automatically detect or block malware. "
    "!!!Malicious traffic can still succeed!!! A clean recording does not prove the image is safe. "
    "Keep secrets out of untrusted builds, review dependencies, and limit CI credentials."
)


@dataclass(frozen=True)
class ImageChoice:
    name: str
    dockerfile: Path
    base: bool
    local_status: str = "missing"
    image_id: str = ""
    runner_abi: str = ""


@dataclass(frozen=True)
class Action:
    key: str
    label: str
    argv: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class WizardStep:
    key: str
    phase: str
    label: str
    status: str
    detail: str
    argv: tuple[str, ...] = ()
    required: bool = True
    evidence: str = ""


@dataclass(frozen=True)
class GuidedPage:
    """One single-image installer page, with executable prerequisite edges."""

    key: str
    phase: str
    label: str
    status: str
    detail: str
    argv: tuple[str, ...] = ()
    required: bool = True
    evidence: str = ""
    kind: str = "action"
    dependencies: tuple[str, ...] = ()
    evidence_token: str = ""
    can_execute: bool = False


def guided_result(page: GuidedPage, status: str) -> dict[str, str]:
    """Bind a transient result to the image/revision observed after the action."""
    return {"status": status, "evidence": page.evidence_token}


def guided_evidence_token(image: ImageChoice | None, state: dict[str, Any],
                          workload: str = "") -> str:
    lane = (state.get("workloads", {}).get(image.name, {}).get(workload, {})
            if image and workload else {})
    revision = lane.get("revision", "")
    decisions = sorted({str(review.get("decisionDigest", "")) for review in lane.get("reviews", [])
                        if isinstance(review, dict) and review.get("decisionDigest")})
    return json.dumps([image.name if image else "", image.image_id if image else "", workload,
                       revision, decisions], separators=(",", ":"))


def load_project_manifest(workspace: Path) -> dict[str, Any] | None:
    path = workspace.resolve() / ".nosh/project.json"
    if not path.exists():
        return None
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or info.st_size > 1024 * 1024:
        raise ValueError(f"unsafe Nosh project manifest: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schemaVersion") != 1 or value.get("kind") != "NoshProject":
        raise ValueError("unsupported Nosh project manifest")
    if set(value) != {"schemaVersion", "kind", "environments", "images", "toolProfiling",
                     "preflight", "policyReferences"}:
        raise ValueError("unknown Nosh project manifest field")
    environments = value.get("environments")
    if (not isinstance(environments, list) or not environments
            or any(item not in ("docker", "qemu") for item in environments)
            or len(set(environments)) != len(environments)):
        raise ValueError("invalid project environments")
    images = value.get("images")
    if not isinstance(images, list):
        raise ValueError("invalid project image selections")
    for image in images:
        if (not isinstance(image, dict)
                or set(image) != {"name", "dockerfile", "buildNetwork", "dev", "run"}
                or not WORKLOAD_IMAGE_NAME.fullmatch(str(image.get("name", "")))):
            raise ValueError("invalid project image name")
        dockerfile = image.get("dockerfile")
        if (not isinstance(dockerfile, str) or not dockerfile
                or Path(dockerfile).is_absolute() or ".." in Path(dockerfile).parts):
            raise ValueError("project Dockerfiles must be safe relative paths")
        if any(type(image.get(key)) is not bool for key in ("buildNetwork", "dev", "run")):
            raise ValueError("invalid project policy-lane selection")
    if type(value.get("toolProfiling")) is not bool or type(value.get("preflight")) is not bool:
        raise ValueError("invalid project option selection")
    references = value.get("policyReferences")
    if not isinstance(references, dict) or not set(references).issubset({"runtime", "toolPolicyDigest"}):
        raise ValueError("invalid project policy references")
    if "toolPolicyDigest" in references and not DIGEST.fullmatch(str(references["toolPolicyDigest"])):
        raise ValueError("invalid project tool-policy digest")
    runtime = references.get("runtime", [])
    if not isinstance(runtime, list):
        raise ValueError("invalid project runtime-policy references")
    for reference in runtime:
        if (not isinstance(reference, dict)
                or not set(reference).issubset({"image", "workload", "imageDigest",
                                                "learnRevision", "decisionDigests"})
                or reference.get("workload") not in ("dev", "run")
                or not WORKLOAD_IMAGE_NAME.fullmatch(str(reference.get("image", "")))):
            raise ValueError("invalid project runtime-policy reference")
        if "imageDigest" in reference and not DIGEST.fullmatch(str(reference["imageDigest"])):
            raise ValueError("invalid project image digest")
        if "learnRevision" in reference and not REVISION.fullmatch(str(reference["learnRevision"])):
            raise ValueError("invalid project learning revision")
        decisions = reference.get("decisionDigests", [])
        if not isinstance(decisions, list) or any(not DIGEST.fullmatch(str(item)) for item in decisions):
            raise ValueError("invalid project decision digest")
    if len({image["name"] for image in images}) != len(images):
        raise ValueError("duplicate project image selection")
    identities = [(reference.get("image"), reference.get("workload")) for reference in runtime]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate project runtime-policy reference")
    return value


def project_manifest(*, workspace: Path, environments: set[str], images: list[ImageChoice],
                     selected: set[str], build_profiles: set[str], dev_profiles: set[str],
                     run_profiles: set[str], tools: bool, preflight: bool,
                     state: dict[str, Any]) -> dict[str, Any]:
    workspace = workspace.resolve()
    chosen = []
    runtime = []
    for image in images:
        if image.name not in selected:
            continue
        if str(image.dockerfile) in ("", "."):
            continue
        try:
            dockerfile = image.dockerfile.resolve().relative_to(workspace).as_posix()
        except (OSError, ValueError):
            continue
        chosen.append({
            "name": image.name,
            "dockerfile": dockerfile,
            "buildNetwork": image.name in build_profiles,
            "dev": image.name in dev_profiles,
            "run": image.name in run_profiles,
        })
        for workload, enabled in (("dev", image.name in dev_profiles),
                                  ("run", image.name in run_profiles)):
            if not enabled:
                continue
            found = state.get("workloads", {}).get(image.name, {}).get(workload, {})
            reference: dict[str, Any] = {"image": image.name, "workload": workload}
            if DIGEST.fullmatch(image.image_id):
                reference["imageDigest"] = image.image_id
            revision = found.get("revision")
            if isinstance(revision, str) and REVISION.fullmatch(revision):
                reference["learnRevision"] = revision
            decisions = sorted({review.get("decisionDigest") for review in found.get("reviews", [])
                                if isinstance(review, dict)
                                and DIGEST.fullmatch(str(review.get("decisionDigest", "")))})
            if decisions:
                reference["decisionDigests"] = decisions
            runtime.append(reference)
    document: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "NoshProject",
        "environments": sorted(environments),
        "images": chosen,
        "toolProfiling": bool(tools),
        "preflight": bool(preflight),
        "policyReferences": {"runtime": runtime},
    }
    tool_digest = state.get("tools", {}).get("policyDigest")
    if DIGEST.fullmatch(str(tool_digest or "")):
        document["policyReferences"]["toolPolicyDigest"] = tool_digest
    return document


def encode_project_manifest(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def guided_project_manifest(*, workspace: Path, image: ImageChoice,
                            build_mode: str | None, stage_choices: dict[str, bool | None],
                            state: dict[str, Any],
                            existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge the current image while retaining other selections and saved evidence."""
    current = project_manifest(
        workspace=workspace, environments={"docker"}, images=[image], selected={image.name},
        build_profiles={image.name} if build_mode == "capture" else set(),
        dev_profiles={image.name} if stage_choices.get("dev") else set(),
        run_profiles={image.name} if stage_choices.get("run") else set(),
        tools=False, preflight=False, state=state,
    )
    if not existing:
        return current
    document = json.loads(json.dumps(existing))
    document["environments"] = sorted(set(document["environments"]) | {"docker"})
    by_name = {entry["name"]: entry for entry in document["images"]}
    by_name.update({entry["name"]: entry for entry in current["images"]})
    document["images"] = list(by_name.values())
    references = document.setdefault("policyReferences", {})
    runtime = {(entry["image"], entry["workload"]): entry
               for entry in references.get("runtime", [])}
    for entry in current["policyReferences"]["runtime"]:
        identity = (entry["image"], entry["workload"])
        if entry.get("learnRevision") or identity not in runtime:
            runtime[identity] = entry
    references["runtime"] = list(runtime.values())
    return document


def save_project_manifest(workspace: Path, document: dict[str, Any]) -> Path:
    root = workspace.resolve() / ".nosh"
    if root.exists() and (not root.is_dir() or root.is_symlink()):
        raise ValueError(f"unsafe Nosh project directory: {root}")
    root.mkdir(mode=0o755, exist_ok=True)
    target = root / "project.json"
    if target.exists() and (not target.is_file() or target.is_symlink()):
        raise ValueError(f"unsafe Nosh project manifest: {target}")
    temporary = root / f".project.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encode_project_manifest(document))
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def discover_images(workspace: Path) -> list[ImageChoice]:
    """Discover workload Dockerfiles without admitting Guard infrastructure."""
    workspace = workspace.resolve()
    images: list[ImageChoice] = []
    base = workspace / "Dockerfile.nosh"
    if base.is_file() and not base.is_symlink():
        images.append(ImageChoice("nosh", base, True))
    for dockerfile in sorted(workspace.glob("Dockerfile.nosh-*")):
        if not dockerfile.is_file() or dockerfile.is_symlink():
            continue
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        name = dockerfile.name.removeprefix("Dockerfile.")
        if not WORKLOAD_IMAGE_NAME.fullmatch(name) or not DERIVED_FROM_BASE.search(text):
            continue
        images.append(ImageChoice(name, dockerfile, False))
    return images


def merge_image_status(images: Iterable[ImageChoice], state: dict[str, Any]) -> list[ImageChoice]:
    by_name = {item.get("name"): item for item in state.get("images", []) if isinstance(item, dict)}
    merged = []
    for image in images:
        found = by_name.get(image.name, {})
        merged.append(ImageChoice(
            image.name,
            image.dockerfile,
            image.base,
            str(found.get("status", "missing")),
            str(found.get("imageId", "")),
            str(found.get("runnerAbi", "")),
        ))
    known = {image.name for image in merged}
    for found in state.get("images", []):
        if not isinstance(found, dict) or found.get("name") in known:
            continue
        dockerfile = Path(str(found.get("dockerfile") or ""))
        merged.append(ImageChoice(
            str(found.get("name")), dockerfile, bool(found.get("base")),
            str(found.get("status", "missing")), str(found.get("imageId", "")),
            str(found.get("runnerAbi", "")),
        ))
    return merged


def _step(repo: Path, workspace: Path, guard_prefix: Path, name: str,
          *, image: str = "", workload: str = "dev",
          extra: tuple[str, ...] = ()) -> tuple[str, ...]:
    command = ["bash", str(repo / "scripts/nosh-init.sh"), "--classic", "--tui-confirmed", "--step", name,
               "--workdir", str(workspace), "--guard-prefix", str(guard_prefix)]
    if image:
        command.extend(("--image", image))
    if workload:
        command.extend(("--workload", workload))
    command.extend(extra)
    return tuple(command)


def _observed_status(session_results: dict[str, str], key: str, fallback: str) -> str:
    result = session_results.get(key)
    if result == "complete":
        return "complete"
    if result == "failed":
        return "blocked"
    return fallback


def _state_status(value: str, complete: str, *, attention: tuple[str, ...] = ()) -> str:
    if value == complete:
        return "complete"
    if value == "blocked":
        return "blocked"
    return "attention" if value in attention else "pending"


def build_guided_pages(*, repo: Path, workspace: Path, guard_prefix: Path,
                       image: ImageChoice | None, state: dict[str, Any],
                       images: list[ImageChoice] | None = None,
                       build_mode: str | None = None,
                       stage_choices: dict[str, bool | None] | None = None,
                       session_results: dict[str, Any] | None = None,
                       skipped: set[str] | None = None,
                       dev_options: tuple[str, ...] = (),
                       run_options: tuple[str, ...] = (),
                       network_options: tuple[str, ...] = ()) -> list[GuidedPage]:
    """Build a dependency-aware installer for exactly one selected workload image.

    Durable evidence comes from the refreshed detector. Only operations without a
    durable detector may use transient results, and those results must match their
    image and learning revision. Skipping a prerequisite propagates only when the
    prerequisite is not already satisfied by verified evidence.
    """
    pages: list[GuidedPage] = []
    by_key: dict[str, GuidedPage] = {}
    session_results = session_results or {}
    skipped = skipped or set()
    stage_choices = stage_choices or {}
    images = images or ([image] if image else [])
    host = state.get("host", {})
    image_token = guided_evidence_token(image, state)
    host_token = json.dumps([str(workspace.resolve()), str(guard_prefix.resolve())])

    def add(key: str, phase: str, label: str, status: str, detail: str,
            argv: tuple[str, ...] = (), *, evidence: str = "", kind: str = "action",
            dependencies: tuple[str, ...] = (), required: bool = True,
            token: str = "", transient: bool = False) -> GuidedPage:
        token = token or image_token
        recorded = session_results.get(key, {})
        recorded_status = (recorded.get("status") if isinstance(recorded, dict)
                           and recorded.get("evidence") == token else None)
        if recorded_status == "failed" and status != "complete":
            status = "blocked"
            evidence = "The last attempt failed. Review Details, then choose Next to retry."
        elif transient and recorded_status == "complete":
            status = "complete"
        if status != "complete":
            if key in skipped:
                status, evidence = "skipped", "Skipped for this setup."
            else:
                unmet = [by_key[dep] for dep in dependencies if by_key[dep].status != "complete"]
                if unmet:
                    omitted = [page for page in unmet if page.status == "skipped"]
                    status = "skipped" if omitted else "blocked"
                    reason = "Skipped because" if omitted else "First complete"
                    evidence = f"{reason}: {', '.join(page.label for page in omitted or unmet)}."
        can_execute = bool(argv and status != "skipped"
                           and all(by_key[dep].status == "complete" for dep in dependencies))
        page = GuidedPage(key, phase, label, status, detail, argv, required, evidence,
                          kind, dependencies, token, can_execute)
        pages.append(page)
        by_key[key] = page
        return page

    add("image:choose", "Image", "Choose one image", "complete" if image else "pending",
        "Build, Dev, and Run policies are configured separately for this image.",
        kind="image")
    if image is None:
        return pages

    name = image.name
    image_ref = image.image_id or name
    available = image.local_status == "available"
    build_selected = build_mode in ("build", "capture")
    found_image = next((entry for entry in state.get("images", [])
                        if entry.get("name") == name), {})
    profile = found_image.get("buildProfile", {})
    profile_path = (profile.get("path", "") if profile.get("status") == "saved"
                    and profile.get("imageDigest") == image.image_id else "")
    add("build:choice", "Build", "Build or reuse the image",
        "complete" if build_mode in ("reuse", "build", "capture", "skip") else "pending",
        "Use a compatible local image, build it, or build it while recording network activity.",
        kind="build-choice", evidence=f"Local image: {image.local_status}.")

    def host_page(key: str, phase: str, label: str, section: str,
                  done: str, command: str, detail: str,
                  dependencies: tuple[str, ...] = ()) -> str:
        if key in by_key:
            return key
        observed = host.get(section, {})
        add(key, phase, label, _state_status(str(observed.get("status", "missing")), done),
            detail, _step(repo, workspace, guard_prefix, command,
                          extra=network_options if command == "network" else ()),
            evidence=str(observed.get("detail", "Not configured yet.")),
            dependencies=dependencies, token=host_token)
        return key

    def guard_pages(phase: str) -> tuple[str, ...]:
        guard = host_page("host:guard", phase, "Initialize Guard", "guard", "present", "install",
                          "Install or update the host service that records and enforces network policy.")
        setup = host_page("host:setup", phase, "Configure launch commands", "launchers", "configured",
                          "setup", "Create the launch commands for this checkout and Guard installation.",
                          (guard,))
        return guard, setup

    def review_pages(phase: str) -> tuple[str, ...]:
        tooling = host_page("host:tooling", phase, "Prepare policy tools", "policyTooling", "ready",
                            "tooling", "Validate or build the offline tools used to inspect network evidence.")
        network = host_page("host:network", phase, "Choose the review network", "reviewNetwork",
                            "configured", "network",
                            "Reserve a private network pool for the isolated review interface.")
        return tooling, network

    def bundled_base(choice: ImageChoice) -> bool:
        return (choice.base and workspace.resolve() == repo.resolve()
                and choice.dockerfile.resolve() == (repo / "Dockerfile.nosh").resolve())

    def base_build_options(choice: ImageChoice) -> tuple[str, ...]:
        return (("--target", "local", "--build-arg", f"USER_UID={os.getuid()}",
                 "--build-arg", f"USER_GID={os.getgid()}") if choice.base else ())

    def image_build_argv(choice: ImageChoice) -> tuple[str, ...]:
        if not choice.dockerfile.is_file() or choice.dockerfile.is_symlink():
            return ()
        if bundled_base(choice):
            return ("env", f"IMAGE_NAME={choice.name}", str(repo / "scripts/build-nosh.sh"))
        return ("docker", "build", "--pull=false", "-f", str(choice.dockerfile),
                "--build-arg", f"USERNAME={getpass.getuser()}", *base_build_options(choice),
                "-t", choice.name, str(workspace))

    if build_selected:
        build_deps: tuple[str, ...] = ("build:choice",)
        if build_mode == "capture":
            build_deps += guard_pages("Build")
        if not image.base:
            base = next((entry for entry in images if entry.base), None)
            base_key = "build:base:nosh"
            add(base_key, "Build", "Prepare the base image",
                "complete" if base and base.local_status == "available" else "pending" if base else "blocked",
                f"{name} uses nosh as its base. This only prepares the dependency for {name}.",
                image_build_argv(base) if base else (),
                evidence=(f"Base image: {base.local_status}." if base else
                          "The base Dockerfile was not found in this workspace."),
                dependencies=("build:choice",), token=host_token)
            build_deps += (base_key,)
        build_argv = image_build_argv(image)
        if build_mode == "capture" and build_argv:
            if bundled_base(image):
                build_argv += ("net", "learn", "--no-review")
            else:
                build_argv = (str(repo / "scripts/nosh.sh"), "build", "net", "learn",
                              "--file", str(image.dockerfile), "--tag", name,
                              "--build-arg", f"USERNAME={getpass.getuser()}",
                              *base_build_options(image), str(workspace))
        add(f"build:execute:{name}", "Build",
            "Build and record network activity for Build Policy" if build_mode == "capture" else "Build the image",
            "pending" if build_argv else "blocked",
            ("Build the selected image once and save its build-network evidence. "
                        "This does not activate a Development or Run policy.\n\n"
                        + BUILD_CAPTURE_DESCRIPTION
                        if build_mode == "capture" else "Build the selected image using its Dockerfile."),
            build_argv, dependencies=build_deps,
            evidence="" if build_argv else "A usable Dockerfile was not found for this image.",
            transient=available and (build_mode != "capture" or bool(profile_path)),
            token=json.dumps([image_token, build_mode]))

    # Runtime availability is independent of a requested rebuild: an existing
    # compatible image remains usable if that rebuild is skipped.
    available_status = "complete" if available else "pending"
    if not available and (build_mode == "skip" or "build:choice" in skipped
                          or f"build:execute:{name}" in skipped):
        available_status = "skipped"
    by_key["image:available"] = GuidedPage(
        "image:available", "Build", "A compatible local image", available_status,
        "Build a compatible image before recording its runtime activity.")

    if build_mode == "capture":
        capture_key = f"build:execute:{name}"
        add(f"build:results:{name}", "Build", "Build recording results",
            "complete" if profile_path and available else "pending",
            "The image build is finished. Review its recorded connections separately; "
            "build evidence does not grant runtime network access.", kind="results",
            evidence=str(profile.get("detail", "No matching completed build recording was found.")),
            dependencies=(capture_key,))
        review_deps = review_pages("Build")
        add(f"build:review:{name}", "Build", "Open build review", "pending",
            "Open the recorded build in Policy Review. Completion here means the viewer opened, "
            "not that decisions were saved or runtime policy was activated.",
            (("env", f"NOSH_PROFILE_REVIEW_WORKDIR={workspace}",
              str(repo / "scripts/profile-build-and-review.sh"), "--build-profile", str(profile_path),
              "--allow-missing-sbom") if profile_path else ()), required=False,
            dependencies=(f"build:results:{name}", *review_deps), transient=True,
            token=json.dumps([image_token, str(profile.get("runId", ""))]))

    workload_state = state.get("workloads", {}).get(name, {})
    for workload, phase in (("dev", "Development (Dev)"), ("run", "Application runtime (Run)")):
        requested = stage_choices.get(workload)
        learn_key = f"{workload}:learn:{name}"
        lane_start = len(pages)
        requested_capture = requested is True and learn_key not in skipped
        guard_deps = guard_pages(phase) if requested_capture else ()
        network = host.get("runtimeNetwork", {})
        readiness_key = f"readiness:{name}"
        if requested_capture and readiness_key not in by_key:
            add(readiness_key, phase, "Check runtime networking",
                "pending" if network.get("status") == "ready" else "blocked",
                "Check IPv6 routing and the Guard backend for this image. Apply any displayed host "
                "network changes yourself, then recheck.",
                _step(repo, workspace, guard_prefix, "readiness", image=image_ref),
                dependencies=("image:available", *guard_deps),
                evidence=str(network.get("detail", "Runtime networking has not been checked.")),
                transient=network.get("status") == "ready")
        rows = workload_state.get(workload, {}).get("steps", {})
        lane_token = guided_evidence_token(image, state, workload)
        learn = rows.get("learn", {})
        app_options = dev_options if workload == "dev" else run_options
        if not any(option in app_options for option in ("--start-app", "--no-start-app")):
            app_options += ("--no-start-app" if workload == "dev" else "--start-app",)
        add(learn_key, phase, f"Record runtime network activity for {workload.capitalize()} Policy",
            _state_status(str(learn.get("status", "missing")), "saved",
                          attention=("stale", "interrupted")),
            f"Record {workload} activity for {name}. Exercise the commands or application connections "
            "you need, then type exit to finish recording and return. A matching saved recording can be reused. "
            "Skip continues without recording or setting up this workload's network policy.",
            _step(repo, workspace, guard_prefix, "learn", image=image_ref, workload=workload,
                  extra=app_options),
            evidence=str(learn.get("detail", "No matching recording was found.")),
            dependencies=(readiness_key,) if requested_capture else ("image:available",),
            kind="recording", token=lane_token)
        # The recording page is the stage choice. Its prerequisite pages appear
        # only after Next requests the stage, never before the initial choice.
        pages.insert(lane_start, pages.pop())
        if requested is not True or learn_key in skipped:
            # Skip is a workflow choice even when a recording already exists.
            # Retain that durable fact, but offer no further actions for this
            # workload until the user returns and chooses Next or Record again.
            continue
        add(f"{workload}:results:{name}", phase, "Runtime recording results",
            "complete" if by_key[learn_key].status == "complete" else "pending",
            "The recording is saved. Next prepares its evidence for review; no policy is active yet.",
            kind="results", dependencies=(learn_key,),
            evidence=f"Learning revision: {workload_state.get(workload, {}).get('revision') or 'not saved'}.",
            token=lane_token)
        recording_skipped = by_key[learn_key].status == "skipped"
        # Do not introduce shared setup solely for a declined recording. A later
        # requested workload introduces these prerequisites at its own pages.
        review_deps = () if recording_skipped else review_pages(phase)
        inventory_key = f"inventory:{name}"
        if not recording_skipped and inventory_key not in by_key:
            inventory = next((workload_state.get(lane, {}).get("steps", {}).get("inventory", {})
                              for lane in ("dev", "run")
                              if workload_state.get(lane, {}).get("steps", {}).get("inventory", {})
                              .get("status") == "saved"), rows.get("inventory", {}))
            add(inventory_key, phase, "Inventory the workspace and image",
                _state_status(str(inventory.get("status", "missing")), "saved",
                              attention=("stale", "incomplete")),
                "Create offline evidence describing the source and this exact image.",
                _step(repo, workspace, guard_prefix, "inventory", image=image_ref, workload=workload),
                evidence=str(inventory.get("detail", "Inventories have not been saved.")),
                dependencies=("image:available", "host:tooling"))
        prepare_key = f"{workload}:prepare:{name}"
        prepare = rows.get("prepare", {})
        add(prepare_key, phase, "Prepare the recorded evidence",
            _state_status(str(prepare.get("status", "missing")), "ready", attention=("stale",)),
            "Freeze the recorded connections and matching inventories into a review bundle.",
            _step(repo, workspace, guard_prefix, "prepare", image=image_ref, workload=workload),
            evidence=str(prepare.get("detail", "Evidence has not been prepared.")),
            dependencies=((learn_key,) if recording_skipped else
                          (learn_key, inventory_key, *review_deps)), token=lane_token)
        review_key = f"{workload}:review:{name}"
        review = rows.get("review", {})
        add(review_key, phase, "Review runtime connections",
            _state_status(str(review.get("status", "missing")), "saved",
                          attention=("stale", "needs-sbom")),
            "Open Policy Review, decide which connections to allow, and save the complete review. "
            "Returning without saving leaves this page unfinished.",
            _step(repo, workspace, guard_prefix, "review", image=image_ref, workload=workload),
            evidence=str(review.get("detail", "No completed matching review was found.")),
            dependencies=(prepare_key,), token=lane_token)
        signing_deps = () if recording_skipped else (
            host_page("host:signing", phase, "Configure policy signing", "signing", "configured",
                      "signing", "Configure review and deployment signing keys and public trust.",
                      ("host:tooling",)),)
        activation = rows.get("activation", {})
        apply_key = f"{workload}:apply:{name}"
        add(apply_key, phase, "Apply the reviewed policy",
            _state_status(str(activation.get("status", "unknown")), "active", attention=("different",)),
            "Validate, sign, and activate the saved decisions for future guarded runs.",
            _step(repo, workspace, guard_prefix, "apply", image=image_ref, workload=workload),
            evidence=str(activation.get("detail", "Activation has not been verified.")),
            dependencies=(review_key, *signing_deps), token=lane_token, transient=True)
        authority = rows.get("authority", {})
        add(f"{workload}:status:{name}", phase, "Verify the active policy",
            "complete" if authority.get("status") == "checked" and activation.get("status") == "active"
            else "pending", "Check live privileged state for this image, workload, and recording revision.",
            _step(repo, workspace, guard_prefix, "status", image=image_ref, workload=workload),
            evidence=str(authority.get("detail", "The active policy has not been verified.")),
            dependencies=(apply_key,), token=lane_token, transient=True)

    summary = ["Image available" if available else "Image unavailable"]
    unfinished = not available or build_mode is None
    if build_selected:
        build_status = by_key[f"build:execute:{name}"].status
        if build_status == "complete":
            summary.append("Build complete with network recording" if build_mode == "capture" else "Build complete")
        elif build_status == "skipped":
            summary.append("Build skipped; requested build unfinished")
        else:
            summary.append("Requested build unfinished")
        unfinished |= build_status != "complete"
    elif build_mode == "reuse":
        summary.append("Build: reused the existing image" if available else "Build: existing image unavailable")
    else:
        summary.append("Build skipped" if build_mode == "skip" else "Build not yet chosen")
    for workload, label in (("dev", "Development"), ("run", "Run")):
        requested = stage_choices.get(workload)
        verified = by_key.get(f"{workload}:status:{name}")
        if requested is True:
            if f"{workload}:learn:{name}" in skipped:
                summary.append(f"{label} recording skipped; existing evidence and policies retained")
            ready = bool(verified and verified.status == "complete")
            summary.append(f"{label} ready" if ready else f"{label} requested but unfinished")
            unfinished |= not ready
        else:
            summary.append(f"{label} not requested" if requested is False else f"{label} not yet chosen")
            unfinished |= requested is None
    add("finish", "Finish", "Setup incomplete" if unfinished else "Setup ready",
        "pending" if unfinished else "complete",
        "Save these choices and portable policy references. Existing policies and other images are retained.",
        kind="finish", evidence="; ".join(summary) + ".")
    return pages


def build_steps(*, repo: Path, workspace: Path, guard_prefix: Path,
                images: list[ImageChoice], selected: set[str],
                build_profiles: set[str], dev_profiles: set[str],
                run_profiles: set[str], tools: bool,
                state: dict[str, Any], preflight: bool = False,
                dev_options: tuple[str, ...] = (), tool_report: str = "",
                tool_digest: str = "", environments: set[str] | None = None,
                qemu_options: tuple[str, ...] = (),
                session_results: dict[str, str] | None = None,
                choices_confirmed: bool = False) -> list[WizardStep]:
    """Return every selected setup step, including completed and skipped work."""
    steps: list[WizardStep] = []
    session_results = session_results or {}
    environments = environments or {"docker"}
    docker_selected = "docker" in environments
    host = state.get("host", {})
    steps.append(WizardStep(
        "project:choices", "Project", "Choose project setup",
        "complete" if choices_confirmed else "pending",
        "Select execution environments, workload images, and the policy lanes to configure.",
        evidence=("Selections confirmed for this session." if choices_confirmed else
                  "Review the choices below, then continue."),
    ))

    if docker_selected and preflight:
        key = "host:preflight"
        steps.append(WizardStep(
            key, "Host setup", "Inspect host networking",
            _observed_status(session_results, key, "pending"),
            "Read-only inspection of Docker, routes, interfaces, and address pools.",
            _step(repo, workspace, guard_prefix, "preflight"), required=False,
            evidence="Selected as an optional host inspection.",
        ))
    else:
        steps.append(WizardStep(
            "host:preflight", "Host setup", "Inspect host networking", "skipped",
            "Optional read-only inspection was not selected.", required=False,
        ))

    if docker_selected:
        guard = host.get("guard", {})
        guard_status = _state_status(str(guard.get("status", "missing")), "present")
        steps.append(WizardStep(
            "host:guard", "Host setup", "Install or update Guard", guard_status,
            "Install the root-owned Guard service and command bundle.",
            _step(repo, workspace, guard_prefix, "install"),
            evidence=str(guard.get("detail", "Guard state unavailable")),
        ))
    else:
        steps.append(WizardStep(
            "host:guard", "Host setup", "Install or update Guard", "skipped",
            "Guard installation is not needed for the selected environment.", required=False,
        ))

    launchers = host.get("launchers", {})
    steps.append(WizardStep(
        "host:setup", "Host setup", "Configure launchers",
        _state_status(str(launchers.get("status", "missing")), "configured"),
        "Install user launch links that point to this checkout and Guard prefix.",
        _step(repo, workspace, guard_prefix, "setup"),
        evidence=str(launchers.get("detail", "Launcher state unavailable")),
    ))

    chosen = [image for image in images if image.name in selected] if docker_selected else []
    if any(not image.base for image in chosen):
        base = next((image for image in images if image.base), None)
        if base and base.name not in {image.name for image in chosen}:
            chosen.insert(0, base)
    runtime_selected = bool(dev_profiles or run_profiles) and docker_selected
    profiles_selected = bool(build_profiles or dev_profiles or run_profiles) and docker_selected

    review_network = host.get("reviewNetwork", {})
    if profiles_selected:
        steps.append(WizardStep(
            "host:network", "Host setup", "Reserve review network pool",
            _state_status(str(review_network.get("status", "missing")), "configured",
                          attention=("invalid", "incomplete")),
            "Reserve checked private subnets used by isolated policy review.",
            _step(repo, workspace, guard_prefix, "network"),
            evidence=str(review_network.get("detail", "Review network state unavailable")),
        ))
    else:
        steps.append(WizardStep(
            "host:network", "Host setup", "Reserve review network pool", "skipped",
            "No Docker policy lane requiring policy review was selected.", required=False,
        ))

    if profiles_selected:
        tooling = host.get("policyTooling", {})
        tooling_fallback = _state_status(str(tooling.get("status", "unchecked")), "ready",
                                         attention=("incompatible", "error"))
        steps.append(WizardStep(
            "host:tooling", "Policy preparation", "Prepare policy tooling",
            _observed_status(session_results, "host:tooling", tooling_fallback),
            "Validate or build the pinned offline policy-tooling image.",
            _step(repo, workspace, guard_prefix, "tooling"),
            evidence=str(tooling.get("detail", "Policy tooling has not been verified.")),
        ))
    else:
        steps.append(WizardStep(
            "host:tooling", "Policy preparation", "Prepare policy tooling", "skipped",
            "No policy profiling lane was selected.", required=False,
        ))

    signing = host.get("signing", {})
    if runtime_selected:
        steps.append(WizardStep(
            "host:signing", "Policy preparation", "Configure signing",
            _state_status(str(signing.get("status", "missing")), "configured"),
            "Create separate review/deployment keys and install their public trust.",
            _step(repo, workspace, guard_prefix, "signing"),
            evidence=str(signing.get("detail", "Signing state unavailable")),
        ))
    else:
        steps.append(WizardStep(
            "host:signing", "Policy preparation", "Configure signing", "skipped",
            "Signing is only required for a selected runtime policy lane.", required=False,
        ))

    for image in chosen:
        key = f"image:{image.name}"
        if image.base:
            argv = ("env", f"IMAGE_NAME={image.name}", str(repo / "scripts/build-nosh.sh"))
        else:
            argv = ("docker", "build", "--pull=false", "-f", str(image.dockerfile),
                    "--build-arg", f"USERNAME={getpass.getuser()}",
                    "-t", image.name, str(workspace))
        status = "complete" if image.local_status == "available" else (
            "attention" if image.local_status == "incompatible" else
            "skipped" if image.name in build_profiles else "pending")
        image_detail = (f"Build {image.dockerfile.name}; derived images require the base image first."
                        if status != "skipped" else
                        "The selected build-network capture builds this image as part of that step.")
        steps.append(WizardStep(
            key, "Images", f"Build workload image: {image.name}", status,
            image_detail, argv, required=status != "skipped", evidence=(f"Local image is {image.local_status}"
                            + (f" ({image.image_id})" if image.image_id else ".")),
        ))
        if image.name in build_profiles:
            if image.base:
                profile_argv = ("env", f"IMAGE_NAME={image.name}",
                                str(repo / "scripts/build-nosh.sh"), "net", "learn")
            else:
                profile_argv = (str(repo / "scripts/nosh.sh"), "build", "net", "learn", "--file",
                                str(image.dockerfile), "--tag", image.name, "--build-arg",
                                f"USERNAME={getpass.getuser()}", str(workspace))
            profile_key = f"build-profile:{image.name}"
            steps.append(WizardStep(
                profile_key, "Images", f"Capture build network: {image.name}",
                _observed_status(session_results, profile_key, "pending"),
                "Capture reviewable build traffic; it is not a runtime activation.",
                profile_argv, required=False,
                evidence="Completion is verified only in the current wizard session.",
            ))

    network = host.get("runtimeNetwork", {})
    for image in chosen:
        image_ref = image.image_id or image.name
        selected_runtime = image.name in dev_profiles or image.name in run_profiles
        if not selected_runtime:
            continue
        readiness_key = f"readiness:{image.name}:{image_ref}"
        if image.local_status != "available":
            readiness_status = "blocked"
            readiness_evidence = "Build a compatible local image before checking Guard readiness."
        elif network.get("status") != "ready":
            readiness_status = "blocked"
            readiness_evidence = str(network.get("detail", "Host IPv6 routing is not ready."))
        else:
            readiness_status = _observed_status(session_results, readiness_key, "pending")
            readiness_evidence = str(network.get("detail", "Live IPv6 checks passed."))
        steps.append(WizardStep(
            readiness_key, "Host readiness", f"Validate runtime host: {image.name}",
            readiness_status,
            "Verify IPv6 routing plus the installed Guard/eBPF backend for this exact image.",
            _step(repo, workspace, guard_prefix, "readiness", image=image_ref),
            evidence=readiness_evidence,
        ))

        rows_by_workload = [
            state.get("workloads", {}).get(image.name, {}).get(workload, {}).get("steps", {})
            for workload in ("dev", "run")
            if image.name in (dev_profiles if workload == "dev" else run_profiles)
        ]
        inventory_state = next((rows.get("inventory", {}) for rows in rows_by_workload
                                if rows.get("inventory", {}).get("status") == "saved"), {})
        inventory_key = f"inventory:{image.name}"
        steps.append(WizardStep(
            inventory_key, "Policy preparation", f"Inventory source and image: {image.name}",
            _observed_status(session_results, inventory_key,
                             _state_status(str(inventory_state.get("status", "missing")), "saved",
                                           attention=("stale", "incomplete"))),
            "Generate offline SPDX evidence for the source tree and exact workload image.",
            _step(repo, workspace, guard_prefix, "inventory", image=image_ref),
            evidence=str(inventory_state.get("detail", "Matching inventories were not found.")),
        ))

        for workload, enabled in (("dev", image.name in dev_profiles),
                                  ("run", image.name in run_profiles)):
            if not enabled:
                continue
            phase = f"{workload.title()} policy — {image.name}"
            rows = state.get("workloads", {}).get(image.name, {}).get(workload, {}).get("steps", {})
            learn = rows.get("learn", {})
            learn_key = f"{workload}:learn:{image.name}"
            steps.append(WizardStep(
                learn_key, phase, "Learn required connections",
                _observed_status(session_results, learn_key,
                                 _state_status(str(learn.get("status", "missing")), "saved",
                                               attention=("stale", "interrupted"))),
                "Run the workload interactively and exercise only the connections it requires.",
                _step(repo, workspace, guard_prefix, "learn", image=image_ref,
                      workload=workload, extra=dev_options if workload == "dev" else ()),
                evidence=str(learn.get("detail", "No matching learning export was found.")),
            ))
            prepare = rows.get("prepare", {})
            prepare_key = f"{workload}:prepare:{image.name}"
            steps.append(WizardStep(
                prepare_key, phase, "Check evidence and prerequisites",
                _observed_status(session_results, prepare_key,
                                 _state_status(str(prepare.get("status", "missing")), "ready",
                                               attention=("blocked", "stale"))),
                "Verify the frozen review bundle, inventories, and policy prerequisites.",
                _step(repo, workspace, guard_prefix, "prepare", image=image_ref,
                      workload=workload),
                evidence=str(prepare.get("detail", "Evidence has not been prepared.")),
            ))
            review = rows.get("review", {})
            review_key = f"{workload}:review:{image.name}"
            steps.append(WizardStep(
                review_key, phase, "Review network decisions",
                _observed_status(session_results, review_key,
                                 _state_status(str(review.get("status", "missing")), "saved",
                                               attention=("stale", "blocked", "needs-sbom"))),
                "Review every proposed connection and save a complete decision set.",
                _step(repo, workspace, guard_prefix, "review", image=image_ref,
                      workload=workload),
                evidence=str(review.get("detail", "No completed matching review was found.")),
            ))
            activation = rows.get("activation", {})
            apply_key = f"{workload}:apply:{image.name}"
            steps.append(WizardStep(
                apply_key, phase, "Apply reviewed policy",
                _observed_status(session_results, apply_key,
                                 _state_status(str(activation.get("status", "unknown")), "active",
                                               attention=("different",))),
                "Validate, sign, and activate the saved selection for future guarded runs.",
                _step(repo, workspace, guard_prefix, "apply", image=image_ref,
                      workload=workload),
                evidence=str(activation.get("detail", "Activation has not been verified.")),
            ))
            authority = rows.get("authority", {})
            verify_key = f"{workload}:status:{image.name}"
            verified = (authority.get("status") == "checked"
                        and activation.get("status") == "active")
            steps.append(WizardStep(
                verify_key, phase, "Verify active policy",
                _observed_status(session_results, verify_key,
                                 "complete" if verified else "pending"),
                "Read privileged live state; saved receipts alone never prove enforcement.",
                _step(repo, workspace, guard_prefix, "status", image=image_ref,
                      workload=workload),
                evidence=str(authority.get("detail", "Privileged status has not been checked this session.")),
            ))

    if not docker_selected or not dev_profiles:
        steps.append(WizardStep(
            "dev:disabled", "Dev policy", "Configure development runtime policy", "skipped",
            "No Docker development policy lane was selected.", required=False,
        ))
    if not docker_selected or not run_profiles:
        steps.append(WizardStep(
            "run:disabled", "Run policy", "Configure production runtime policy", "skipped",
            "No Docker run policy lane was selected.", required=False,
        ))

    if tools and docker_selected:
        tool_state = state.get("tools", {})
        tool_active = tool_state.get("status") == "active"
        for command_name, label in (("tools-init", "Collect tool history"),
                                    ("tools-review", "Review tool activity and environment"),
                                    ("tools-check", "Check tool policy"),
                                    ("tools-apply", "Apply tool environment policy"),
                                    ("tools-status", "Verify tool policy")):
            extra: tuple[str, ...] = ()
            if command_name != "tools-init" and tool_report:
                extra += ("--review", tool_report)
            if command_name == "tools-apply" and tool_digest:
                extra += ("--policy-digest", tool_digest)
            key = f"tools:{command_name}"
            fallback = "complete" if command_name == "tools-apply" and tool_active else "pending"
            if command_name == "tools-status":
                observed = session_results.get(key)
                status = ("blocked" if observed == "failed" else
                          "complete" if observed == "complete" and tool_active else "pending")
            else:
                status = _observed_status(session_results, key, fallback)
            steps.append(WizardStep(
                key, "Tool policy", label, status,
                "Optional development-tool environment policy; this grants no network access.",
                _step(repo, workspace, guard_prefix, command_name, extra=extra), required=False,
                evidence=str(tool_state.get("detail", "Tool policy is not active.")),
            ))
    else:
        steps.append(WizardStep(
            "tools:disabled", "Tool policy", "Configure tool environment policy", "skipped",
            "Optional tool profiling was not selected.", required=False,
        ))

    if "qemu" in environments:
        for key, label, argv in (
            ("qemu:start", "Prepare and start QEMU environment",
             (str(repo / "scripts/nosh.sh"), "--qemu", "start", "--detach",
              "--workdir", str(workspace), *qemu_options)),
            ("qemu:status", "Verify QEMU environment",
             (str(repo / "scripts/nosh.sh"), "--qemu", "status", "--workdir", str(workspace))),
        ):
            steps.append(WizardStep(
                key, "QEMU", label, _observed_status(session_results, key, "pending"),
                "Provision or inspect the persistent VM and its managed Docker guest.",
                argv, required=False,
                evidence="QEMU lifecycle status is verified in the current wizard session.",
            ))
    else:
        steps.append(WizardStep(
            "qemu:disabled", "QEMU", "Configure QEMU environment", "skipped",
            "QEMU was not selected.", required=False,
        ))

    unfinished = any(step.status not in ("complete", "skipped") for step in steps)
    finish_status = ("complete" if not unfinished and session_results.get("finish") == "complete"
                     else "pending")
    steps.append(WizardStep(
        "finish", "Finish", "Finish project setup",
        finish_status,
        "Review the result, save portable project references, and show the exact start command.",
        evidence=("Complete the remaining required steps first." if unfinished else
                  "All selected steps are complete or explicitly skipped."),
    ))
    return steps


def build_queue(*, session_results: dict[str, str] | None = None,
                choices_confirmed: bool = True, **kwargs: Any) -> list[Action]:
    """Create the Advanced-mode queue from incomplete actionable wizard steps."""
    return [
        Action(step.key, step.label, step.argv, step.detail)
        for step in build_steps(session_results=session_results,
                                choices_confirmed=choices_confirmed, **kwargs)
        if step.argv and step.status not in ("complete", "skipped")
    ]
