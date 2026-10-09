#!/usr/bin/env python3
"""Resumable host TUI for Nosh setup and policy profiling."""

from __future__ import annotations

import argparse
import asyncio
import difflib
import json
from pathlib import Path
import shlex
import subprocess
import sys

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header, Input, Label, Log,
    RadioButton, RadioSet, Select, SelectionList, Static,
)
from textual.widgets.selection_list import Selection
from nosh_policy_ui import MoreMenu, PolicyManager

from nosh_init_model import (
    Action, BUILD_CAPTURE_DESCRIPTION, GuidedPage, ImageChoice, build_guided_pages, build_queue, discover_images,
    guided_project_manifest, guided_result,
    encode_project_manifest, load_project_manifest, merge_image_status, project_manifest,
    save_project_manifest,
)


def highlight_build_capture_description(value: str) -> Text:
    description = Text(value)
    for phrase in ("supply-chain attacks", "secret-stealing code", "malware detection",
                   "!!!Malicious traffic can still succeed!!!"):
        start = value.find(phrase)
        if start >= 0:
            description.stylize("bold red", start, start + len(phrase))
    return description


class ConfirmAction(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ConfirmAction { align: center middle; }
    #dialog { width: 90%; height: 85%; border: heavy $accent; padding: 1 2; background: $surface; }
    #command { margin: 1 0; height: 1fr; overflow-y: auto; }
    #buttons { height: 3; align: right middle; }
    #buttons Button { margin-left: 1; }
    """

    def __init__(self, action: Action) -> None:
        super().__init__()
        self.action = action

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"Run: {self.action.label}", markup=False)
            yield Static(self.action.detail, markup=False)
            yield Static(shlex.join(self.action.argv), id="command", markup=False)
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Run", id="run", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == "run")

    def action_cancel(self):
        self.dismiss(False)


class ConfirmManifest(ModalScreen[bool]):
    CSS = """
    ConfirmManifest { align: center middle; }
    #manifest-dialog { width: 90%; height: 85%; border: heavy $accent; padding: 1 2; background: $surface; }
    #manifest-diff { height: 1fr; overflow-y: auto; }
    #manifest-buttons { height: 3; align: right middle; }
    #manifest-buttons Button { margin-left: 1; }
    """

    def __init__(self, difference: str) -> None:
        super().__init__()
        self.difference = difference

    def compose(self) -> ComposeResult:
        with Vertical(id="manifest-dialog"):
            yield Label("Save portable repository configuration and policy references?")
            yield Static(self.difference, id="manifest-diff", markup=False)
            with Horizontal(id="manifest-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save .nosh/project.json", id="save", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "save")


class NoshInitApp(App[None]):
    TITLE = "Nosh Project Setup"
    SUB_TITLE = "one image at a time"
    CSS = """
    #summary { height: auto; min-height: 3; padding: 0 2; border-bottom: solid $primary; }
    #guided-body, #advanced-body { height: 1fr; }
    #page-scroll { height: 1fr; padding: 0 2; }
    #step-title { height: auto; margin: 1 0; color: $text; text-style: bold; }
    #step-state { height: auto; margin-bottom: 1; }
    #step-detail, #step-evidence { height: auto; margin-bottom: 1; }
    #step-evidence { padding: 1; border: round $secondary; }
    #image-choice, #build-choice, #network-choice { height: auto; margin-bottom: 1; }
    #build-options { height: auto; }
    #build-capture-help { height: auto; margin: 1 0; }
    #start-app { height: auto; margin-bottom: 1; }
    #step-command { height: auto; padding: 1; background: $boost; }
    #next-effect { height: auto; min-height: 2; padding: 0 2; }
    #navigation { height: 3; padding: 0 1; align: right middle; }
    #navigation Button { margin-left: 1; min-width: 10; }
    #navigation-spacer { width: 1fr; }
    #advanced-left { width: 3fr; }
    #advanced-right { width: 2fr; border-left: solid $primary; }
    .section-title { height: auto; color: $accent; text-style: bold; margin-top: 1; }
    DataTable { height: 1fr; }
    #environments { height: 5; }
    #queue { height: 2fr; }
    #details { height: 1fr; border-top: solid $primary; }
    """
    BINDINGS = [
        Binding("n", "next_step", "Next", key_display="N"),
        Binding("p", "previous_step", "Previous", key_display="P"),
        Binding("s", "skip_step", "Skip", key_display="S"),
        Binding("N", "next_step", "Next", show=False),
        Binding("P", "previous_step", "Previous", show=False),
        Binding("S", "skip_step", "Skip", show=False),
        Binding("escape", "back_step", "Previous", show=False),
        Binding("a", "toggle_advanced", "Advanced"),
        Binding("space", "toggle_image", "Select image"),
        Binding("b", "toggle_build_profile", "Build net"),
        Binding("d", "toggle_dev", "Dev net"),
        Binding("r", "toggle_run", "Run net"),
        Binding("t", "toggle_tools", "Tools"),
        Binding("p", "toggle_preflight", "Preflight"),
        Binding("g", "refresh", "Recheck"),
        Binding("s", "save_project", "Save refs"),
        Binding("x", "execute", "Run queue"),
        Binding("q", "quit", "Quit"),
    ]
    STATUS_SYMBOLS = {
        "complete": "✓", "pending": "○", "attention": "⚠",
        "blocked": "✗", "skipped": "—",
    }

    def __init__(self, *, repo: Path, workspace: Path, guard_prefix: Path,
                 requested_image: str = "", default_workload: str = "dev",
                 dev_options: tuple[str, ...] = (), tool_report: str = "",
                 tool_digest: str = "", qemu_options: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.repo = repo.resolve()
        self.workspace = workspace.resolve()
        self.guard_prefix = guard_prefix
        self.requested_image = requested_image
        self.default_workload = default_workload
        self.dev_options = dev_options
        self.tool_report = tool_report
        self.tool_digest = tool_digest
        self.qemu_options = qemu_options
        self.state: dict = {}
        self.images: list[ImageChoice] = []
        self.image_rows: list[str] = []
        # Advanced selections remain independent of the single-image walk-through.
        self.selected: set[str] = set()
        self.build_profiles: set[str] = set()
        self.dev_profiles: set[str] = set()
        self.run_profiles: set[str] = set()
        self.tools = False
        self.preflight = False
        self.environments: set[str] = {"docker"}
        self.actions: list[Action] = []
        self.session_results: dict[str, str] = {}
        self.project: dict | None = None
        self.advanced_mode = False
        self.syncing_controls = False
        self.show_command = False
        self.guided_image_name = ""
        self.candidate_image_name = ""
        self.build_mode: str | None = None
        self.stage_choices: dict[str, bool | None] = {"dev": None, "run": None}
        self.pending_capture: tuple[str, str, tuple[str, ...]] | None = None
        self.capture_context: str | None = None
        self.guided_results: dict = {}
        self.guided_skipped: set[str] = set()
        self.guided_pages: list[GuidedPage] = []
        self.page_key = "image:choose"
        self.page_history: list[str] = []
        self.start_apps = {"dev": False, "run": True}
        self.saved_finish = False
        self.network_pool = ""
        self.network_exclusions = ""
        self.network_suggestions: list[str] = []
        self.last_result = ""
        self.state_error = ""

    @staticmethod
    def environment_choices(identifier: str) -> SelectionList:
        return SelectionList(
            ("Docker — build/dev/run/tool policy workflow", "docker", True),
            ("QEMU — persistent VM with managed Docker guest", "qemu", False),
            Selection("bwrap — not implemented", "bwrap", False, disabled=True),
            id=identifier,
        )

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="summary", markup=False)
        with Vertical(id="guided-body"):
            yield Static(id="next-effect", markup=False)
            with VerticalScroll(id="page-scroll"):
                yield Label(id="step-title", markup=False)
                yield Static(id="step-state", markup=False)
                yield Static(id="step-detail", markup=False)
                with Vertical(id="image-choice"):
                    yield Select([], prompt="Select one image", id="image-select")
                with Vertical(id="build-choice"):
                    with RadioSet(id="build-options"):
                        yield RadioButton("Use existing compatible image", id="build-reuse")
                        yield RadioButton("Build image", id="build-plain")
                        yield RadioButton("Build and capture network activity", id="build-capture")
                    yield Label("Why capture build traffic?", classes="section-title")
                    yield Static(highlight_build_capture_description(BUILD_CAPTURE_DESCRIPTION),
                                 id="build-capture-help", markup=False)
                with Vertical(id="network-choice"):
                    yield Label("Additional LAN/VPN ranges to avoid (optional)", classes="section-title")
                    yield Input(placeholder="192.168.10.0/24, 10.80.0.0/16", id="network-exclusions")
                    yield Button("Find available pools", id="network-suggest")
                    yield Select([], prompt="Select a suggested pool", id="network-pools")
                    yield Label("Review network pool (suggested or custom)", classes="section-title")
                    yield Input(placeholder="Private IPv4 /26 pool", id="network-pool")
                    yield Static(id="network-result", markup=False)
                yield Checkbox("Start bundled application during recording", id="start-app")
                yield Static(id="step-evidence", markup=False)
                yield Button("Open policy editor…", id="policy-editor")
                yield Button("Record again", id="rerun")
                yield Button("Another image", id="another-image")
                yield Static(id="step-command", markup=False)
            with Horizontal(id="navigation"):
                yield Button("More…", id="more")
                yield Static(id="navigation-spacer")
                yield Button("Previous", id="back")
                yield Button("Skip", id="skip")
                yield Button("Next", id="next", variant="primary")
        with Horizontal(id="advanced-body"):
            with Vertical(id="advanced-left"):
                yield Button("Return to Guided", id="guided")
                yield Label("Execution environments", classes="section-title")
                yield self.environment_choices("environments")
                yield Static(id="advanced-options", markup=False)
                yield Label("Host setup", classes="section-title")
                yield DataTable(id="host")
                yield Label("Workload images and policy lanes", classes="section-title")
                yield DataTable(id="images")
            with Vertical(id="advanced-right"):
                yield Label("Remaining action queue", classes="section-title")
                yield DataTable(id="queue")
                yield Log(id="details", highlight=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#advanced-body").display = False
        for identifier, columns in (
                ("host", ("Item", "Status", "Detail")),
                ("images", ("Use", "Image", "Local", "Build", "Dev", "Run")),
                ("queue", ("#", "Action"))):
            table = self.query_one("#" + identifier, DataTable)
            table.add_columns(*columns)
            table.cursor_type = "row"
        try:
            self.project = load_project_manifest(self.workspace)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.log_detail(f"Project manifest ignored: {error}")
        self.refresh_state(initial=True)
        self.query_one("#image-select", Select).focus()

    def log_detail(self, message: str) -> None:
        self.query_one("#details", Log).write_line(message)

    def load_state(self) -> dict:
        command = [sys.executable, str(self.repo / "scripts/nosh-init-status.py"),
                   "--json", "--all-workloads", "--workdir", str(self.workspace),
                   "--guard-prefix", str(self.guard_prefix), "--repo", str(self.repo)]
        if self.requested_image:
            command.extend(("--image", self.requested_image))
        if self.tool_report:
            command.extend(("--review", self.tool_report))
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"status exited {result.returncode}")
        value = json.loads(result.stdout)
        if value.get("schemaVersion") != 1:
            raise RuntimeError("unsupported initialization status schema")
        return value

    def refresh_state(self, *, initial: bool = False) -> bool:
        try:
            self.state = self.load_state()
            self.state_error = ""
            if self.state.get("host", {}).get("runtimeNetwork", {}).get("status") != "ready":
                for key in list(self.guided_results):
                    if key.startswith("readiness:"):
                        self.guided_results.pop(key, None)
            self.images = merge_image_status(discover_images(self.workspace), self.state)
            if self.pending_capture:
                image = self.current_image_choice()
                if not image or image.image_id != self.pending_capture[1]:
                    self.pending_capture = None
                    self.last_result = "The selected image changed. Return to the recording page to request capture again."
            if initial:
                if self.project:
                    self.environments = set(self.project["environments"])
                    self.tools = self.project["toolProfiling"]
                    self.preflight = self.project["preflight"]
                    for configured in self.project["images"]:
                        name = configured["name"]
                        if name in {image.name for image in self.images}:
                            self.selected.add(name)
                            for field, lane in (("buildNetwork", self.build_profiles),
                                                ("dev", self.dev_profiles), ("run", self.run_profiles)):
                                if configured[field]:
                                    lane.add(name)
                requested = next((image.name for image in self.images
                                  if self.requested_image and (image.name == self.requested_image
                                  or image.image_id == self.requested_image)), "")
                self.candidate_image_name = requested or next(
                    (image.name for image in self.images if image.name in self.selected),
                    self.images[0].name if self.images else "")
            self.sync_controls()
            self.render_state()
            self.log_detail("State refreshed. Actions revalidate saved evidence before use.")
            return True
        except Exception as error:
            self.pending_capture = None
            self.state_error = str(error)
            self.log_detail(f"State refresh failed: {error}")
            self.notify(f"State refresh failed: {error}", severity="error")
            self.render_state()
            return False

    def sync_controls(self) -> None:
        self.syncing_controls = True
        try:
            selector = self.query_one("#image-select", Select)
            with selector.prevent(Select.Changed):
                selector.set_options([(f"{image.name} — {image.local_status}", image.name)
                                      for image in self.images])
                selector.value = (self.candidate_image_name
                                  if self.candidate_image_name in {image.name for image in self.images}
                                  else Select.NULL)
            environments = self.query_one("#environments", SelectionList)
            with environments.prevent(SelectionList.SelectedChanged):
                environments.deselect_all()
                for value in self.environments:
                    environments.select(value)
        finally:
            self.syncing_controls = False

    def current_image_choice(self) -> ImageChoice | None:
        return next((image for image in self.images if image.name == self.guided_image_name), None)

    def model_arguments(self) -> dict:
        return {
            "repo": self.repo, "workspace": self.workspace, "guard_prefix": self.guard_prefix,
            "images": self.images, "selected": self.selected,
            "build_profiles": self.build_profiles, "dev_profiles": self.dev_profiles,
            "run_profiles": self.run_profiles, "tools": self.tools, "state": self.state,
            "preflight": self.preflight, "dev_options": self.dev_options,
            "tool_report": self.tool_report, "tool_digest": self.tool_digest,
            "environments": self.environments, "qemu_options": self.qemu_options,
            "session_results": self.session_results,
        }

    def rebuild_guided_pages(self) -> None:
        self.guided_pages = build_guided_pages(
            repo=self.repo, workspace=self.workspace, guard_prefix=self.guard_prefix,
            images=self.images, image=self.current_image_choice(), state=self.state,
            build_mode=self.build_mode, stage_choices=self.stage_choices,
            session_results=self.guided_results, skipped=self.guided_skipped,
            dev_options=self.dev_options, run_options=(),
        )
        if self.page_key not in {page.key for page in self.guided_pages}:
            self.page_key = "image:choose"

    def render_state(self) -> None:
        host_table = self.query_one("#host", DataTable)
        host_table.clear()
        for key, label in (("guard", "Guard"), ("launchers", "Launchers"),
                           ("reviewNetwork", "Review network"), ("runtimeNetwork", "Runtime IPv6"),
                           ("policyTooling", "Policy tools"), ("signing", "Signing")):
            item = self.state.get("host", {}).get(key, {})
            host_table.add_row(label, str(item.get("status", "unknown")), str(item.get("detail", "")))
        table = self.query_one("#images", DataTable)
        previous_name = self.image_rows[table.cursor_row] if self.image_rows and 0 <= table.cursor_row < len(self.image_rows) else ""
        self.image_rows = [image.name for image in self.images]
        with table.prevent(DataTable.RowHighlighted):
            table.clear()
            for image in self.images:
                table.add_row(
                    "yes" if image.name in self.selected else "no", image.name, image.local_status,
                    "yes" if image.name in self.build_profiles else "no",
                    "yes" if image.name in self.dev_profiles else "no",
                    "yes" if image.name in self.run_profiles else "no",
                )
            if previous_name in self.image_rows:
                table.move_cursor(row=self.image_rows.index(previous_name))
        self.actions = build_queue(**self.model_arguments())
        queue = self.query_one("#queue", DataTable)
        queue.clear()
        for index, action in enumerate(self.actions, 1):
            queue.add_row(str(index), action.label)
        self.query_one("#advanced-options", Static).update(
            f"Tool policy: {'yes' if self.tools else 'no'}  |  "
            f"Host preflight: {'yes' if self.preflight else 'no'}")
        self.rebuild_guided_pages()
        self.render_page()

    @property
    def current_page(self) -> GuidedPage | None:
        return next((page for page in self.guided_pages if page.key == self.page_key), None)

    @staticmethod
    def status_icon(symbol: str) -> Text:
        return Text(symbol, style={"✓": "green", "○": "red", "✗": "red",
                                  "⚠": "yellow", "—": "dim"}.get(symbol, ""))

    def render_context(self) -> None:
        context = Text()
        context.append("Workspace: ", style="bold cyan")
        context.append(str(self.workspace))
        context.append("\nImage: ", style="bold magenta")
        context.append((self.candidate_image_name if self.page_key == "image:choose" else
                        self.guided_image_name) or "Choose an image")
        context.append("    Policy: ", style="bold cyan")
        policy = self.policy_context()
        context.append(policy or "—", style=self.policy_color(policy))
        self.query_one("#summary", Static).update(context)

    @staticmethod
    def policy_color(policy):
        return {"Build": "bold bright_yellow", "Dev": "bold bright_blue", "Run": "bold bright_red"}.get(policy, "default")

    def policy_context(self):
        page = self.current_page
        if self.advanced_mode or not page or page.kind in ("image", "finish"):
            return ""
        if self.capture_context and self.is_capture_prerequisite(page):
            return self.capture_context.split(":")[0].capitalize()
        return "Dev" if page.phase.startswith("Development") else "Run" if page.phase.startswith("Application") else "Build" if page.phase == "Build" else ""

    def page_dependencies_ready(self, page: GuidedPage) -> bool:
        by_key = {item.key: item for item in self.guided_pages}
        image = self.current_image_choice()
        return all((bool(image and image.local_status == "available") if key == "image:available"
                    else key in by_key and by_key[key].status == "complete")
                   for key in page.dependencies)

    def page_evidence(self, page: GuidedPage) -> str:
        lines = [page.evidence] if page.evidence else []
        if "readiness" in page.key:
            network = self.state.get("host", {}).get("runtimeNetwork", {})
            for check in network.get("checks", []):
                lines.append(f"{check.get('label', 'Check')}: {check.get('detail', '')}")
                if check.get("status") in ("fail", "warning") and check.get("remediation"):
                    lines.append(f"  {check['remediation']}")
            lines.extend((
                "",
                "These are guarded Docker runtime requirements. Change host settings deliberately, then Recheck.",
                "The wizard does not change sysctls or firewall rules.",
                "Verify forwarding: cat /proc/sys/net/ipv6/conf/all/forwarding",
                "Verify the route: ip -6 route show default",
                "If the uplink uses router advertisements, accept_ra=2 preserves them while forwarding.",
                "After validating temporary settings, persist reviewed values in /etc/sysctl.d/90-nosh-ipv6.conf:",
                "  net.ipv6.conf.all.forwarding=1",
                "  net.ipv6.conf.default.forwarding=1",
                "Retain the host firewall configuration.",
            ))
            interface = network.get("routeInterface")
            if interface and network.get("routeUsesRouterAdvertisements"):
                lines.append(f"  net.ipv6.conf.{interface}.accept_ra=2")
        if page.kind == "finish":
            unfinished = [item for item in self.guided_pages
                          if item.kind == "action" and item.status != "complete"]
            if unfinished:
                lines.append("\nNot completed:")
                for item in unfinished:
                    status = "skipped" if item.status == "skipped" else "unfinished"
                    lines.append(f"  {item.phase}: {item.label} — {status}")
            lines.append("\nSaved project references describe your choices; verification checks current policy state.")
        if self.last_result:
            lines.append("\n" + self.last_result)
        if self.state_error:
            lines.append("\nCould not refresh state: " + self.state_error)
        return "\n".join(lines)

    def render_page(self) -> None:
        page = self.current_page
        self.render_context()
        if page is None:
            return
        title = Text(page.label)
        policy = self.policy_context()
        suffix = f"{policy} Policy"
        if policy and suffix in page.label:
            title.stylize(self.policy_color(policy), page.label.index(suffix))
        self.query_one("#step-title", Label).update(title)
        if page.kind in ("image", "build-choice"):
            status_text = ("Choose an image, then Next" if page.kind == "image" else
                           "Choose how to prepare this image")
            state_label = Text(status_text, style="bold cyan")
        else:
            labels = {"complete": "Already complete", "pending": "Not yet completed",
                      "blocked": "Needs attention", "attention": "Needs attention", "skipped": "Skipped"}
            if page.kind == "recording" or (page.key.startswith("build:execute:") and self.build_mode == "capture"):
                labels["complete"] = "Saved recording available"
            state_label = self.status_icon(self.STATUS_SYMBOLS.get(page.status, "○"))
            state_label.append(" " + labels.get(page.status, page.status), style="default")
        self.query_one("#step-state", Static).update(state_label)
        self.query_one("#step-state", Static).display = page.kind != "image"
        detail = (highlight_build_capture_description(page.detail)
                  if page.key.startswith("build:execute:") and self.build_mode == "capture"
                  else page.detail)
        self.query_one("#step-detail", Static).update(detail)
        self.query_one("#image-choice").display = page.kind == "image"
        self.query_one("#build-choice").display = page.kind == "build-choice"
        network_step = page.key == "host:network" and page.status != "complete"
        self.query_one("#network-choice").display = network_step
        recording = page.kind == "recording"
        checkbox = self.query_one("#start-app", Checkbox)
        checkbox.display = recording
        if recording:
            workload = page.key.split(":")[0]
            with checkbox.prevent(Checkbox.Changed):
                checkbox.value = self.start_apps[workload]
        evidence = self.query_one("#step-evidence", Static)
        evidence_text = self.page_evidence(page)
        evidence.display = bool(evidence_text)
        evidence.update(evidence_text)
        details = self.query_one("#step-command", Static)
        details.display = self.show_command
        details.update(("Command:\n" + shlex.join(self.command_for(page))) if page.argv else
                       "No command runs on this page.")
        self.query_one("#back", Button).disabled = not self.page_history
        self.query_one("#skip", Button).disabled = (page.kind in ("image", "finish")
            or (page.status == "complete" and page.kind != "build-choice"
                and not recording and not self.is_capture_prerequisite(page)))
        self.query_one("#skip", Button).label = "Skip recording" if recording else "Skip"
        self.query_one("#policy-editor").display = ":review:" in page.key
        self.query_one("#rerun", Button).display = recording and page.status == "complete"
        self.query_one("#rerun", Button).disabled = not self.can_record_again(page)
        self.query_one("#another-image", Button).display = page.kind == "finish"
        next_button = self.query_one("#next", Button)
        next_button.label = "Close" if page.kind == "finish" and self.saved_finish else (
            "Finish" if page.kind == "finish" else "Next")
        disabled = bool(self.state_error)
        if page.kind == "image":
            disabled = disabled or not self.candidate_image_name
        elif recording:
            image = self.current_image_choice()
            disabled = disabled or not image or image.local_status != "available"
        elif page.kind == "action" and page.status != "complete":
            disabled = disabled or not self.page_dependencies_ready(page)
            disabled = disabled or not page.argv
            if "readiness" in page.key and self.state.get("host", {}).get("runtimeNetwork", {}).get("status") != "ready":
                disabled = True
            if network_step and not self.network_pool.strip():
                disabled = True
        elif page.kind == "results" and page.status != "complete":
            disabled = True
        next_button.disabled = disabled
        if page.kind == "image":
            effect = "Next will show build options. No build starts yet."
        elif page.kind == "build-choice":
            effect = "Next will prepare the selected build workflow."
        elif recording and not disabled:
            if page.status == "complete":
                effect = "Next will reuse the saved recording. Skip leaves this workload unrequested."
            else:
                effect = ("Next will start capture." if self.capture_ready() else
                          "Next will guide required setup, then automatically start capture.")
                effect += " Skip leaves this workload unrequested."
        elif self.pending_capture:
            effect = "Complete this prerequisite to continue toward capture. Previous or Skip cancels automatic capture."
        elif page.kind == "finish":
            effect = "Finish will review and save this image's project references." if not self.saved_finish else "Project references saved. Close to exit."
        elif page.status == "complete" or page.kind == "results":
            effect = "Next will continue without repeating completed work."
        elif disabled:
            effect = "Resolve the prerequisite and Recheck, or Skip to continue with independent work."
        else:
            effect = "Next will " + page.label[:1].lower() + page.label[1:] + "."
        self.query_one("#next-effect", Static).update("Next: " + effect.removeprefix("Next will "))
        self.refresh_bindings()

    def command_for(self, page: GuidedPage) -> tuple[str, ...]:
        argv = page.argv
        if ":learn:" in page.key:
            workload = page.key.split(":")[0]
            argv = tuple(arg for arg in argv if arg not in ("--start-app", "--no-start-app"))
            argv += ("--start-app" if self.start_apps[workload] else "--no-start-app",)
        if page.key == "host:network":
            argv += ("--review-pool", self.network_pool.strip())
            for excluded in self.network_exclusions.replace(",", " ").split():
                argv += ("--exclude", excluded)
        return argv

    def can_record_again(self, page: GuidedPage) -> bool:
        return bool(":learn:" in page.key and page.argv and not self.state_error
                    and self.current_image_choice()
                    and self.current_image_choice().local_status == "available")

    def capture_ready(self) -> bool:
        image = self.current_image_choice()
        by_key = {page.key: page for page in self.guided_pages}
        return bool(image and image.local_status == "available"
                    and self.state.get("host", {}).get("runtimeNetwork", {}).get("status") == "ready"
                    and all(key in by_key and by_key[key].status == "complete"
                            for key in ("host:guard", "host:setup", f"readiness:{image.name}")))

    def is_capture_prerequisite(self, page: GuidedPage) -> bool:
        return bool(self.capture_context and page.key in (
            "host:guard", "host:setup", f"readiness:{self.guided_image_name}"))

    async def request_capture(self, page: GuidedPage, *, force: bool = False) -> None:
        self.pending_capture = None
        self.capture_context = page.key
        self.saved_finish = False
        self.stage_choices[page.key.split(":")[0]] = True
        for key in (page.key, "host:guard", "host:setup", f"readiness:{self.guided_image_name}"):
            self.guided_skipped.discard(key)
        self.render_state()
        page = self.current_page
        if page.status == "complete" and not force:
            self.capture_context = None
            self.set_page(page.key.replace(":learn:", ":results:"))
            return
        image = self.current_image_choice()
        if not image or image.local_status != "available" or self.state_error:
            return
        self.pending_capture = (page.key, image.image_id, self.command_for(page))
        await self.continue_capture()

    async def continue_capture(self) -> None:
        intent = self.pending_capture
        if not intent:
            return
        key, image_id, argv = intent
        image = self.current_image_choice()
        by_key = {page.key: page for page in self.guided_pages}
        page = by_key.get(key)
        if (self.state_error or not image or image.image_id != image_id or not page
                or self.stage_choices.get(key.split(":")[0]) is not True):
            self.pending_capture = None
            return
        for prerequisite in ("host:guard", "host:setup", f"readiness:{image.name}"):
            item = by_key.get(prerequisite)
            if not item or item.status == "skipped":
                self.pending_capture = None
                return
            if item.status != "complete":
                self.set_page(prerequisite)
                return
        if not self.capture_ready():
            self.pending_capture = None
            self.set_page(key)
            return
        # Consume intent before executing so refresh/back/retry cannot replay it.
        self.pending_capture = None
        self.capture_context = None
        self.set_page(key, remember=False)
        await self.run_guided_page(page, argv=argv)

    def set_page(self, key: str, *, remember: bool = True) -> None:
        if (remember and key != self.page_key
                and (not self.page_history or self.page_history[-1] != self.page_key)):
            self.page_history.append(self.page_key)
        self.page_key = key
        self.show_command = False
        self.last_result = ""
        self.render_page()
        self.query_one("#page-scroll", VerticalScroll).scroll_home(animate=False)
        if self.current_page and self.current_page.kind == "image":
            self.query_one("#image-select", Select).focus()
        elif self.current_page and self.current_page.kind == "build-choice":
            self.select_default_build_option()
            self.query_one("#build-options", RadioSet).focus()
        else:
            self.query_one("#next", Button).focus()

    def advance(self, key: str) -> None:
        index = next((i for i, page in enumerate(self.guided_pages) if page.key == key), -1)
        for page in self.guided_pages[index + 1:]:
            if page.status != "skipped" or page.kind in ("recording", "finish"):
                self.set_page(page.key)
                return

    def select_default_build_option(self) -> None:
        image = self.current_image_choice()
        available = image is not None and image.local_status == "available"
        self.query_one("#build-reuse", RadioButton).disabled = not available
        mode = self.build_mode or ("reuse" if available else "capture")
        identifier = {"reuse": "build-reuse", "build": "build-plain", "capture": "build-capture"}.get(mode, "build-capture")
        self.query_one("#" + identifier, RadioButton).value = True

    def reset_guided(self, image_name: str) -> None:
        self.pending_capture = None
        self.capture_context = None
        self.guided_image_name = image_name
        self.build_mode = None
        self.stage_choices = {"dev": None, "run": None}
        self.guided_results.clear()
        self.guided_skipped.clear()
        self.page_history.clear()
        self.saved_finish = False
        self.last_result = ""
        self.network_pool = ""
        self.network_exclusions = ""
        self.start_apps = {"dev": False, "run": True}

    def on_select_changed(self, event: Select.Changed) -> None:
        if self.syncing_controls:
            return
        if event.select.id == "image-select":
            self.pending_capture = None
            self.candidate_image_name = "" if event.value is Select.NULL else str(event.value)
            self.render_page()
        elif event.select.id == "network-pools" and event.value is not Select.NULL:
            self.query_one("#network-pool", Input).value = str(event.value)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "network-pool":
            self.network_pool = event.value
            self.render_page()
        elif event.input.id == "network-exclusions":
            self.network_exclusions = event.value

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        page = self.current_page
        if event.checkbox.id == "start-app" and page and ":learn:" in page.key:
            self.start_apps[page.key.split(":")[0]] = event.value

    @work(exclusive=True, group="network-suggestions")
    async def action_suggest_network(self) -> None:
        command = [sys.executable, "-I", "-S", str(self.repo / "scripts/nosh-review-network.py"), "suggest"]
        for value in self.network_exclusions.replace(",", " ").split():
            command.extend(("--exclude", value))
        self.query_one("#network-result", Static).update("Inspecting local routes and Docker allocations…")
        try:
            result = await asyncio.to_thread(subprocess.run, command, capture_output=True,
                                             text=True, timeout=45, check=False)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Host inspection failed")
            document = json.loads(result.stdout)
            if document.get("schemaVersion") != 1 or document.get("status") != "checked":
                raise ValueError("Host inspection did not complete")
            pools = [str(item["pool"]) for item in document.get("suggestions", [])]
            self.network_suggestions = pools
            selector = self.query_one("#network-pools", Select)
            selector.set_options([(pool, pool) for pool in pools])
            if pools:
                selector.value = pools[0]
            self.query_one("#network-result", Static).update(
                "Select a suggested pool or enter a custom one. Host checks run again before saving."
                if pools else "No pool was suggested. Enter a custom private pool or Skip.")
        except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
            self.query_one("#network-result", Static).update(str(error))

    def action_previous_step(self) -> None:
        if not self.advanced_mode:
            self.action_back_step()

    def action_back_step(self) -> None:
        self.pending_capture = None
        if self.advanced_mode:
            self.action_toggle_advanced()
            return
        available = {page.key for page in self.guided_pages}
        while self.page_history:
            key = self.page_history.pop()
            if key in available:
                self.set_page(key, remember=False)
                return

    def action_skip_step(self) -> None:
        if self.advanced_mode:
            return
        page = self.current_page
        if page is None or page.kind in ("image", "finish") or (
                page.status == "complete" and page.kind not in ("recording", "build-choice")
                and not self.is_capture_prerequisite(page)):
            return
        self.saved_finish = False
        capture_key = page.key if page.kind == "recording" else self.capture_context
        self.pending_capture = None
        if capture_key and (page.kind == "recording" or page.key in (
                "host:guard", "host:setup", f"readiness:{self.guided_image_name}")):
            self.capture_context = None
            self.stage_choices[capture_key.split(":")[0]] = False
            self.guided_skipped.add(capture_key)
            self.page_key = capture_key
            self.render_state()
            self.set_page(f"run:learn:{self.guided_image_name}" if capture_key.startswith("dev:") else "finish")
            return
        elif page.kind == "build-choice":
            self.build_mode = "reuse" if self.current_image_choice() and self.current_image_choice().local_status == "available" else "skip"
        else:
            self.guided_skipped.add(page.key)
        self.render_state()
        self.advance(page.key)

    async def execute_command(self, argv: tuple[str, ...]) -> int:
        with self.suspend():
            try:
                result = subprocess.run(argv, cwd=self.repo, check=False)
                code = result.returncode
            except (OSError, KeyboardInterrupt) as error:
                print(f"Action interrupted or unavailable: {error}")
                code = 130 if isinstance(error, KeyboardInterrupt) else 1
            try:
                input("Press Enter to return to Nosh Setup…")
            except (EOFError, KeyboardInterrupt):
                pass
        return code

    async def run_guided_page(self, page: GuidedPage, *, argv: tuple[str, ...] | None = None) -> None:
        argv = argv or self.command_for(page)
        if not argv:
            return
        self.saved_finish = False
        self.log_detail("Running: " + shlex.join(argv))
        try:
            result = await self.execute_command(argv)
        except asyncio.CancelledError:
            self.pending_capture = None
            raise
        self.guided_skipped.discard(page.key)
        # Non-build results remain bound to the input image/revision. Build success
        # binds the newly inspected output, since its tag can now identify a new image.
        if result:
            self.pending_capture = None
            self.guided_results[page.key] = guided_result(page, "failed")
            self.refresh_state()
            self.last_result = f"Action exited with status {result}. Retry with Next or Skip this work."
            self.render_page()
            return
        if not page.key.startswith("build:execute:"):
            self.guided_results[page.key] = guided_result(page, "complete")
        if not self.refresh_state():
            return
        refreshed = next((item for item in self.guided_pages if item.key == page.key), None)
        if page.key.startswith("build:execute:") and refreshed:
            self.guided_results[page.key] = guided_result(refreshed, "complete")
            self.render_state()
            refreshed = next((item for item in self.guided_pages if item.key == page.key), None)
        if refreshed and refreshed.status == "complete":
            if self.pending_capture:
                await self.continue_capture()
            elif self.capture_context and page.key in (
                    "host:guard", "host:setup", f"readiness:{self.guided_image_name}"):
                self.set_page(self.capture_context)
            elif page.kind == "recording":
                self.set_page(page.key.replace(":learn:", ":results:"))
            else:
                self.advance(page.key)
        else:
            self.pending_capture = None
            self.last_result = "The command returned. Completion is not yet verified; finish any review, then Recheck."
            self.render_page()

    @work(exclusive=True, group="guided-action")
    async def action_next_step(self) -> None:
        if self.advanced_mode or self.query_one("#next", Button).disabled:
            return
        page = self.current_page
        if page is None:
            return
        if page.kind == "recording":
            await self.request_capture(page)
        elif page.kind == "image":
            if self.candidate_image_name != self.guided_image_name:
                self.reset_guided(self.candidate_image_name)
            self.render_state()
            self.advance(page.key)
        elif page.kind == "build-choice":
            selected = self.query_one("#build-options", RadioSet).pressed_button
            build_mode = {"build-reuse": "reuse", "build-plain": "build",
                          "build-capture": "capture"}.get(selected.id if selected else "", "capture")
            if build_mode != self.build_mode:
                self.saved_finish = False
            self.build_mode = build_mode
            self.guided_skipped.discard(f"build:execute:{self.guided_image_name}")
            self.render_state()
            self.advance(page.key)
        elif page.kind == "finish":
            if self.saved_finish:
                self.exit()
            elif await self.save_project():
                self.saved_finish = True
                self.render_page()
        elif page.status == "complete" or page.kind == "results":
            if self.pending_capture:
                await self.continue_capture()
            elif self.is_capture_prerequisite(page):
                self.set_page(self.capture_context)
            else:
                self.advance(page.key)
        elif page.argv:
            await self.run_guided_page(page)

    @work(exclusive=True, group="guided-action")
    async def action_rerun_step(self) -> None:
        page = self.current_page
        if page and self.can_record_again(page) and not self.advanced_mode:
            await self.request_capture(page, force=True)

    @work(exclusive=True, group="guided-action")
    async def action_another_image(self) -> None:
        if not self.saved_finish and not await self.save_project():
            return
        self.reset_guided("")
        self.page_key = "image:choose"
        self.render_state()
        self.query_one("#image-select", Select).focus()

    def action_refresh(self) -> None:
        self.last_result = ""
        self.saved_finish = False
        self.refresh_state()

    def action_toggle_command(self) -> None:
        self.show_command = not self.show_command
        self.render_page()

    def action_toggle_advanced(self) -> None:
        self.pending_capture = None
        self.advanced_mode = not self.advanced_mode
        self.query_one("#guided-body").display = not self.advanced_mode
        self.query_one("#advanced-body").display = self.advanced_mode
        self.render_state()
        (self.query_one("#images", DataTable) if self.advanced_mode else
         self.query_one("#next", Button)).focus()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in ("toggle_image", "toggle_build_profile", "toggle_dev", "toggle_run"):
            return self.advanced_mode and isinstance(self.focused, DataTable) and self.focused.id == "images"
        if action in ("toggle_tools", "toggle_preflight", "save_project", "execute"):
            return self.advanced_mode
        if action in ("next_step", "previous_step", "skip_step"):
            return not self.advanced_mode
        return super().check_action(action, parameters)

    def current_image(self) -> str | None:
        if not self.advanced_mode or self.focused is not self.query_one("#images", DataTable):
            return None
        index = self.query_one("#images", DataTable).cursor_row
        return self.image_rows[index] if 0 <= index < len(self.image_rows) else None

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        if event.selection_list.id != "environments" or self.syncing_controls:
            return
        selected = set(event.selection_list.selected)
        if not selected:
            with event.selection_list.prevent(SelectionList.SelectedChanged):
                event.selection_list.select("docker")
            selected = {"docker"}
        self.environments = selected
        self.render_state()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "queue" and 0 <= event.cursor_row < len(self.actions):
            action = self.actions[event.cursor_row]
            self.log_detail(action.detail + "\n" + shlex.join(action.argv))

    def action_toggle_image(self) -> None:
        name = self.current_image()
        if not name:
            return
        image = next(item for item in self.images if item.name == name)
        if image.base and any(value != name for value in self.selected):
            self.notify("The base image is required by a selected derived image.")
            return
        if name in self.selected:
            self.selected.remove(name)
            for lane in (self.build_profiles, self.dev_profiles, self.run_profiles):
                lane.discard(name)
        else:
            self.selected.add(name)
            if not image.base:
                self.selected.update(item.name for item in self.images if item.base)
        self.render_state()

    def toggle_lane(self, lane: set[str]) -> None:
        name = self.current_image()
        if not name or "docker" not in self.environments:
            return
        self.selected.add(name)
        if name in lane:
            lane.remove(name)
        else:
            lane.add(name)
        if any(item.name == name and not item.base for item in self.images):
            self.selected.update(item.name for item in self.images if item.base)
        self.render_state()

    def action_toggle_build_profile(self) -> None:
        self.toggle_lane(self.build_profiles)

    def action_toggle_dev(self) -> None:
        self.toggle_lane(self.dev_profiles)

    def action_toggle_run(self) -> None:
        self.toggle_lane(self.run_profiles)

    def action_toggle_tools(self) -> None:
        if self.advanced_mode:
            self.tools = not self.tools
            self.render_state()

    def action_toggle_preflight(self) -> None:
        if self.advanced_mode:
            self.preflight = not self.preflight
            self.render_state()

    async def save_project(self) -> bool:
        try:
            if self.advanced_mode:
                document = project_manifest(
                    workspace=self.workspace, environments=self.environments, images=self.images,
                    selected=self.selected, build_profiles=self.build_profiles,
                    dev_profiles=self.dev_profiles, run_profiles=self.run_profiles,
                    tools=self.tools, preflight=self.preflight, state=self.state)
            else:
                image = self.current_image_choice()
                if image is None:
                    return False
                # Re-read so configuring another image cannot overwrite newer references.
                existing = load_project_manifest(self.workspace)
                document = guided_project_manifest(
                    existing=existing, workspace=self.workspace, image=image,
                    build_mode=self.build_mode, stage_choices=self.stage_choices, state=self.state)
            encoded = encode_project_manifest(document)
            target = self.workspace / ".nosh/project.json"
            current = target.read_text(encoding="utf-8") if target.is_file() and not target.is_symlink() else ""
            difference = "".join(difflib.unified_diff(
                current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                fromfile=".nosh/project.json (current)", tofile=".nosh/project.json (proposed)",
            )) or "No changes."
            if not await self.push_screen_wait(ConfirmManifest(difference)):
                return False
            path = save_project_manifest(self.workspace, document)
            self.project = document
            self.log_detail(f"Saved portable references: {path}")
            self.notify("Saved .nosh/project.json")
            return True
        except (OSError, ValueError) as error:
            self.notify(f"Project save failed: {error}", severity="error")
            return False

    @work(exclusive=True, group="save-project")
    async def action_save_project(self) -> None:
        await self.save_project()

    @work(exclusive=True, group="advanced-action")
    async def action_execute(self) -> None:
        if not self.advanced_mode:
            return
        # Refresh each next action; previous commands can change the selected image ID.
        attempted: set[str] = set()
        while True:
            action = next((item for item in self.actions if item.key not in attempted), None)
            if action is None:
                return
            attempted.add(action.key)
            if not await self.push_screen_wait(ConfirmAction(action)):
                continue
            self.saved_finish = False
            result = await self.execute_command(action.argv)
            if result:
                self.session_results[action.key] = "failed"
                self.refresh_state()
                self.notify(f"{action.label} failed ({result})", severity="error")
                return
            if (action.key == "host:preflight" or action.key.startswith(("build-profile:", "readiness:", "qemu:", "tools:"))
                    or ":apply:" in action.key or ":status:" in action.key):
                self.session_results[action.key] = "complete"
            else:
                self.session_results.pop(action.key, None)
            self.refresh_state()

    def action_more(self):
        def chosen(value):
            action = {"policies": self.action_manage_policies, "details": self.action_toggle_command,
                      "refresh": self.action_refresh, "advanced": self.action_toggle_advanced}.get(value)
            if action:
                action()
        self.push_screen(MoreMenu(), chosen)

    def action_manage_policies(self):
        policy = self.policy_context().lower() or "dev"
        self.pending_capture = None
        self.capture_context = None
        original_image = self.guided_image_name
        def returned(recording):
            if recording:
                if original_image != self.guided_image_name:
                    self.reset_guided(self.guided_image_name)
                self.build_mode = "capture" if recording == "build" else "reuse"
                self.render_state()
                target = (f"build:execute:{self.guided_image_name}" if recording == "build" else
                          f"{recording}:learn:{self.guided_image_name}")
                self.set_page(target)
            else:
                self.render_page()
        self.push_screen(PolicyManager(ConfirmAction, policy), returned)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = {
            "advanced": self.action_toggle_advanced, "guided": self.action_toggle_advanced,
            "back": self.action_back_step, "skip": self.action_skip_step,
            "next": self.action_next_step, "command-details": self.action_toggle_command,
            "recheck": self.action_refresh, "rerun": self.action_rerun_step,
            "another-image": self.action_another_image, "network-suggest": self.action_suggest_network,
            "more": self.action_more, "policy-editor": self.action_manage_policies,
        }.get(event.button.id)
        if action:
            action()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--guard-prefix", required=True, type=Path)
    parser.add_argument("--image", default="")
    parser.add_argument("--default-workload", choices=("dev", "run"), default="dev")
    parser.add_argument("--agents", default="auto")
    parser.add_argument("--codex-home", default="")
    parser.add_argument("--agent-baseline", action="append", default=[])
    parser.add_argument("--review", default="")
    parser.add_argument("--policy-digest", default="")
    args = parser.parse_args()
    if not args.workdir.is_dir():
        parser.error("--workdir must be an existing directory")
    dev_options = ("--agents", args.agents)
    if args.codex_home:
        dev_options += ("--codex-home", args.codex_home)
    for baseline in args.agent_baseline:
        dev_options += ("--agent-baseline", baseline)
    qemu_options = ("--codex-home", args.codex_home) if args.codex_home else ()
    NoshInitApp(repo=args.repo, workspace=args.workdir, guard_prefix=args.guard_prefix,
                requested_image=args.image, default_workload=args.default_workload,
                dev_options=dev_options, tool_report=args.review,
                tool_digest=args.policy_digest, qemu_options=qemu_options).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
