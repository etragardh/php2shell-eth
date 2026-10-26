"""Slim, fail-closed target-contract navigator and exact-plan runner."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
import shlex
import sys

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.worker import Worker, WorkerError
from textual.widgets import Button, Input, Label, RichLog, Select, Static, TextArea

from core.catalog import (
    ARCHITECTURES,
    INI_CONTRACTS,
    RELEASES,
    RUNTIME_PRODUCTS,
    SAPI_BY_ID,
    ProfileCatalog,
    ProfileResolution,
    QualificationStatus,
    mutable_image_alias,
)
from core.runplan import PlanError, RunDraft, RunPlan, VerifierMode, freeze_run_plan
from profiles import PROFILE_CATALOG


LineSink = Callable[[str], None]
PlanRunner = Callable[[RunPlan, LineSink], Awaitable[int]]


def execution_argv(plan: RunPlan) -> tuple[str, ...]:
    """Return the shell-free argv used by the TUI for one frozen plan."""
    source_entry = Path(__file__).resolve().parents[1] / "php2shell-eth.py"
    prefix = (
        (sys.executable, "-u", str(source_entry))
        if source_entry.is_file()
        else (sys.executable, "-u", "-m", "cli")
    )
    return (*prefix, *plan.argv()[1:])


_AXES = (
    ("php_release", "php-release"),
    ("sapi", "sapi"),
    ("runtime_product", "runtime-product"),
    ("architecture", "architecture"),
    ("ini_contract_id", "ini-contract"),
)
_PROMPTS = {
    "php_release": "Choose release",
    "sapi": "Choose execution model",
    "runtime_product": "Choose image lineage",
    "architecture": "Choose container platform",
    "ini_contract_id": "Choose ini contract",
}
_WAITING_PROMPTS = {
    "sapi": "Choose release first",
    "runtime_product": "Choose execution model first",
    "architecture": "Choose runtime first",
    "ini_contract_id": "Choose architecture first",
}


def _axis_label(field: str, value: str) -> str:
    if field == "php_release":
        match = next((item for item in RELEASES if item.release == value), None)
        return match.label if match is not None else f"PHP {value}"
    if field == "sapi":
        return SAPI_BY_ID[value].label
    if field == "runtime_product":
        match = next((item for item in RUNTIME_PRODUCTS if item.id == value), None)
        return match.label if match is not None else value
    if field == "architecture":
        match = next((item for item in ARCHITECTURES if item.id == value), None)
        return (
            f"{match.label} · {match.oci_platform}"
            if match is not None
            else value
        )
    if field == "ini_contract_id":
        contract = INI_CONTRACTS.get(value)
        return contract.label if contract is not None else value
    raise ValueError(f"unknown TUI axis: {field}")


@dataclass(frozen=True)
class SelectionDraft:
    php_release: str | None
    sapi: str | None
    runtime_product: str | None
    architecture: str | None
    ini_contract_id: str | None

    @property
    def complete(self) -> bool:
        return all((
            self.php_release,
            self.sapi,
            self.runtime_product,
            self.architecture,
            self.ini_contract_id,
        ))


class RunOutputModal(ModalScreen[None]):
    """Large live-output dialog for one exact run plan."""

    BINDINGS = []
    DEFAULT_CSS = """
    RunOutputModal {
        align: center middle;
        background: #08060d 76%;
    }
    #run-output-dialog {
        width: 92%;
        height: 86%;
        max-width: 150;
        max-height: 48;
        padding: 1 2;
        background: #171322;
        border: solid #6757a0;
    }
    #run-output-header {
        height: 2;
    }
    #run-output-title {
        width: 1fr;
        color: #5ee6f2;
        text-style: bold;
    }
    #run-output-status {
        width: auto;
        padding: 0 1;
        color: #f2c66d;
        background: #342919;
    }
    #run-output-status.success {
        color: #71e6b0;
        background: #173126;
    }
    #run-output-status.warning {
        color: #f2c66d;
        background: #342919;
    }
    #run-output-status.error {
        color: #ff8896;
        background: #351a26;
    }
    #run-output-profile {
        height: 2;
        color: #847a9b;
    }
    #run-output {
        height: 1fr;
        padding: 0 1;
        background: #0b0912;
        border: solid #3b3154;
        color: #e8e3f3;
        scrollbar-size: 1 1;
    }
    #run-output-footer {
        height: 2;
        padding-top: 1;
    }
    #run-output-help {
        width: 1fr;
        color: #847a9b;
    }
    #close-run-output {
        width: 12;
        height: 1;
        min-width: 12;
        padding: 0 1;
        border: none;
        background: #292342;
        color: #5ee6f2;
    }
    #close-run-output:disabled {
        background: #1c1729;
        color: #665e78;
    }
    """

    def __init__(self, profile_id: str) -> None:
        super().__init__()
        self.profile_id = profile_id

    def compose(self) -> ComposeResult:
        with Vertical(id="run-output-dialog"):
            with Horizontal(id="run-output-header"):
                yield Static("» RUN OUTPUT", id="run-output-title", markup=False)
                yield Static("RUNNING", id="run-output-status", markup=False)
            yield Static(self.profile_id, id="run-output-profile", markup=False)
            yield RichLog(
                id="run-output",
                markup=False,
                highlight=False,
                wrap=False,
                auto_scroll=True,
            )
            with Horizontal(id="run-output-footer"):
                yield Static(
                    "Live stdout + stderr · Ctrl+Q stops and quits",
                    id="run-output-help",
                    markup=False,
                )
                yield Button(
                    "Close",
                    id="close-run-output",
                    disabled=True,
                    compact=True,
                    flat=True,
                )

    def prepare(self, profile_id: str) -> None:
        self.profile_id = profile_id
        self.query_one("#run-output-profile", Static).update(profile_id)
        status = self.query_one("#run-output-status", Static)
        for class_name in ("success", "warning", "error"):
            status.remove_class(class_name)
        status.update("RUNNING")
        self.query_one("#close-run-output", Button).disabled = True
        self.query_one("#run-output", RichLog).clear()

    def write_line(self, line: str) -> None:
        self.query_one("#run-output", RichLog).write(line)

    def finish(self, exit_code: int | None) -> None:
        status = self.query_one("#run-output-status", Static)
        if exit_code is None:
            label, class_name = "RUNNER ERROR", "error"
        elif exit_code == 0:
            label, class_name = "COMPLETED · EXIT 0", "success"
        else:
            label, class_name = f"COMPLETED · EXIT {exit_code}", "warning"
        for name in ("success", "warning", "error"):
            status.remove_class(name)
        status.add_class(class_name)
        status.update(label)
        self.query_one("#close-run-output", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-run-output":
            event.stop()
            self.dismiss()


class Php2ShellApp(App[None]):
    TITLE = "php2shell-eth"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+r", "run", "Run", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    CSS = """
    Screen {
        layout: vertical;
        background: #100d18;
        color: #e8e3f3;
    }
    #header {
        height: 4;
        padding: 1 2 0 2;
        border-bottom: solid #3b3154;
    }
    #identity { width: 1fr; height: 2; }
    #scope-badge {
        width: auto;
        height: 1;
        padding: 0 1;
        margin-top: 1;
        background: #1c1729;
        color: #a98cff;
    }
    #workspace {
        height: 1fr;
        layout: horizontal;
        margin: 1 1 0 1;
    }
    #contract-panel {
        width: 52%;
        min-width: 42;
        height: 1fr;
        padding: 0 1;
        scrollbar-size: 1 1;
    }
    #resolution-panel {
        width: 1fr;
        height: 1fr;
        padding: 0 1 0 2;
        border-left: solid #3b3154;
    }
    .panel-title {
        height: 2;
        color: #b8aecf;
        text-style: bold;
    }
    .section-title {
        height: 2;
        padding-top: 1;
        color: #847a9b;
        text-style: bold;
    }
    .field-row { height: 2; }
    .field-row Label {
        width: 20;
        height: 1;
        padding-right: 1;
        color: #b8aecf;
        text-wrap: nowrap;
    }
    .field-row Input, .field-row Select {
        width: 1fr;
        height: 1;
    }
    Input, Select, SelectCurrent, TextArea {
        background: #241e34;
        color: #e8e3f3;
    }
    Input.-textual-compact { padding: 0 1; }
    Select.-textual-compact > SelectCurrent { padding: 0 1; }
    Input:focus, Select:focus > SelectCurrent {
        background: #232640;
        color: #5ee6f2;
        background-tint: transparent;
    }
    SelectOverlay {
        height: auto;
        min-height: 0;
        max-height: 10;
        background: #1c1729;
        border: solid #6757a0;
        color: #e8e3f3;
        scrollbar-size: 1 1;
    }
    SelectOverlay > .option-list--option-highlighted {
        background: #292342;
        color: #5ee6f2;
    }
    #arch-note, #selection-hint, #run-hint {
        height: auto;
        color: #847a9b;
    }
    #arch-note { margin: 0 0 1 20; }
    #summary {
        height: auto;
        min-height: 12;
        padding: 1;
        background: #15111f;
        border: solid #3b3154;
        color: #e8e3f3;
    }
    #summary.candidate { border: solid #92733a; }
    #summary.supported { border: solid #3e8d73; }
    #summary.unavailable, #summary.rejected, #summary.retired { border: solid #914152; }
    #matrix-status {
        height: auto;
        margin-top: 1;
        color: #847a9b;
    }
    #action-row {
        height: 2;
        padding: 0 2;
    }
    Button {
        height: 1;
        min-width: 7;
        padding: 0 1;
        border: none;
        background: #100d18;
        color: #b8aecf;
        text-style: none;
    }
    Button:hover, Button:focus {
        background: #292342;
        color: #5ee6f2;
        text-style: none;
    }
    Button:disabled { color: #665e78; background: #100d18; }
    #run { width: 12; color: #5ee6f2; }
    #run:disabled { color: #665e78; }
    #review { width: 19; color: #b8aecf; }
    #review:disabled { color: #665e78; }
    #reset { width: 9; }
    #run-hint { width: 1fr; height: 1; padding-left: 1; }
    #preview-row { height: 2; padding: 0 2; }
    #preview-label { width: 8; height: 1; color: #847a9b; }
    #command-preview {
        width: 1fr;
        height: 1;
        padding: 0;
        background: #100d18;
        color: #b8aecf;
        scrollbar-size: 0 0;
    }
    #command-preview:focus { background: #1c1729; }
    #keymap { height: 1; padding: 0 2; color: #847a9b; }
    #contract-panel, #resolution-panel {
        scrollbar-background: #100d18;
        scrollbar-color: #514469;
        scrollbar-color-hover: #7564a0;
        scrollbar-color-active: #5ee6f2;
    }
    Screen.narrow #workspace {
        layout: vertical;
        overflow-y: auto;
    }
    Screen.narrow #contract-panel,
    Screen.narrow #resolution-panel {
        width: 1fr;
        min-width: 0;
        height: auto;
        min-height: 18;
    }
    Screen.narrow #resolution-panel {
        border-left: none;
        border-top: solid #3b3154;
        padding: 1;
    }
    Screen.compact #header { height: 3; padding-top: 0; }
    Screen.compact #identity { height: 1; }
    Screen.compact #scope-badge { margin-top: 0; }
    Screen.short #workspace { margin-top: 0; }
    Screen.short .field-row { height: 1; margin-bottom: 1; }
    """

    def __init__(
        self,
        catalog: ProfileCatalog = PROFILE_CATALOG,
        *,
        runner: PlanRunner | None = None,
    ) -> None:
        super().__init__()
        self.catalog = catalog
        self.resolution: ProfileResolution | None = None
        self.plan: RunPlan | None = None
        self._updating = False
        self._runner = runner
        self._run_active = False
        self._active_plan: RunPlan | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._run_worker: Worker[int | None] | None = None
        self._output_modal: RunOutputModal | None = None
        self.run_transcript: list[str] = []

    def compose(self) -> ComposeResult:
        with Horizontal(id="header"):
            yield Static(self._identity(), id="identity", markup=False)
            yield Static("PROFILE CATALOG · EXACT RUN PLAN", id="scope-badge", markup=False)
        with Horizontal(id="workspace"):
            with VerticalScroll(id="contract-panel"):
                yield Label("TARGET CONTRACT", classes="panel-title")
                with Horizontal(classes="field-row"):
                    yield Label("PHP release")
                    yield Select(
                        [
                            (_axis_label("php_release", value), value)
                            for value in self.catalog.values("php_release")
                        ],
                        allow_blank=True,
                        prompt="Choose release",
                        id="php-release",
                        compact=True,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Execution model")
                    yield Select(
                        [],
                        allow_blank=True,
                        prompt="Choose release first",
                        id="sapi",
                        compact=True,
                        disabled=True,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Runtime product")
                    yield Select(
                        [],
                        allow_blank=True,
                        prompt="Choose image lineage",
                        id="runtime-product",
                        compact=True,
                        disabled=True,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Target architecture")
                    yield Select(
                        [],
                        allow_blank=True,
                        prompt="Choose container platform",
                        id="architecture",
                        compact=True,
                        disabled=True,
                    )
                yield Static(
                    "",
                    id="arch-note",
                    markup=False,
                )
                with Horizontal(classes="field-row"):
                    yield Label("Ini contract")
                    yield Select(
                        [],
                        allow_blank=True,
                        prompt="Choose runtime first",
                        id="ini-contract",
                        compact=True,
                        disabled=True,
                    )
                yield Label("RUN DRAFT", classes="section-title")
                with Horizontal(classes="field-row"):
                    yield Label("Target URL")
                    yield Input(
                        placeholder="http://host:port/index.php",
                        id="target-url",
                        compact=True,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("MaxRequestWorkers")
                    yield Input(
                        placeholder="select target contract",
                        type="integer",
                        id="workers",
                        compact=True,
                        disabled=True,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Command")
                    yield Input(placeholder="no default command", id="command", compact=True)
                with Horizontal(classes="field-row"):
                    yield Label("Verification")
                    yield Select(
                        [("None · outcome may be unconfirmed", "none"), ("HTTP path", "http")],
                        value="none",
                        allow_blank=False,
                        id="verifier-mode",
                        compact=True,
                    )
                with Horizontal(classes="field-row"):
                    yield Label("Verify path")
                    yield Input(placeholder="/proof.txt", id="verify-path", compact=True, disabled=True)
                with Horizontal(classes="field-row"):
                    yield Label("Expected text")
                    yield Input(placeholder="fresh nonce", id="verify-text", compact=True, disabled=True)
                with Horizontal(classes="field-row"):
                    yield Label("Evidence directory")
                    yield Input(placeholder="optional new directory", id="evidence-dir", compact=True)
            with Vertical(id="resolution-panel"):
                yield Label("RESOLVED PROFILE", classes="panel-title")
                yield Static("Select the target axes.", id="summary", markup=False)
                yield Static(
                    f"{len(self.catalog.tracks)} manifest/disposition tracks · "
                    f"{len(self.catalog.profiles)} profile leaves\n",
                    id="matrix-status",
                    markup=False,
                )
        with Horizontal(id="action-row"):
            yield Button("Run · ctrl+r", id="run", disabled=True, compact=True, flat=True)
            yield Button("Profile required", id="review", disabled=True, compact=True, flat=True)
            yield Button("Reset", id="reset", compact=True, flat=True)
            yield Static("Complete an exact target contract and run draft.", id="run-hint", markup=False)
        with Horizontal(id="preview-row"):
            yield Label("CLI", id="preview-label")
            yield TextArea(
                "# select an exact target contract",
                read_only=True,
                soft_wrap=False,
                show_line_numbers=False,
                highlight_cursor_line=False,
                compact=True,
                id="command-preview",
            )
        yield Static("ctrl+r run   ctrl+q quit", id="keymap")

    def on_mount(self) -> None:
        self._resize(self.size.width, self.size.height)
        self._sync_axis_options()
        self.query_one("#php-release", Select).focus()
        self._refresh()

    def on_resize(self, event) -> None:
        self._resize(event.size.width, event.size.height)

    def _resize(self, width: int, height: int) -> None:
        self.screen.set_class(width < 88, "narrow")
        self.screen.set_class(width < 108 or height < 25, "compact")
        self.screen.set_class(height < 28, "short")

    @staticmethod
    def _identity() -> Text:
        value = Text("» php2shell-eth «", style="bold #a98cff", no_wrap=True)
        value.append("\nexact target-contract runner", style="#847a9b")
        return value

    @staticmethod
    def _value(select: Select) -> str | None:
        return None if select.value is Select.NULL else str(select.value)

    def _selection(self) -> SelectionDraft:
        return SelectionDraft(
            self._value(self.query_one("#php-release", Select)),
            self._value(self.query_one("#sapi", Select)),
            self._value(self.query_one("#runtime-product", Select)),
            self._value(self.query_one("#architecture", Select)),
            self._value(self.query_one("#ini-contract", Select)),
        )

    def _clear(self, *ids: str) -> None:
        for widget_id in ids:
            widget = self.query_one(f"#{widget_id}", Select)
            with widget.prevent(Select.Changed):
                widget.value = Select.NULL

    def _sync_axis_options(self) -> None:
        """Derive every selector from the surviving catalog entries."""
        selected = {
            field: self._value(self.query_one(f"#{widget_id}", Select))
            for field, widget_id in _AXES
        }
        for index, (field, widget_id) in enumerate(_AXES):
            prior_fields = [item[0] for item in _AXES[:index]]
            ready = all(selected[item] is not None for item in prior_fields)
            filters = {item: selected[item] for item in prior_fields} if ready else {}
            values = self.catalog.values(field, **filters) if ready else ()
            widget = self.query_one(f"#{widget_id}", Select)
            current = selected[field]
            with widget.prevent(Select.Changed):
                widget.set_options([
                    (_axis_label(field, value), value) for value in values
                ])
                widget.value = current if current in values else Select.NULL
                widget.disabled = not ready or not values
                widget.prompt = (
                    _PROMPTS[field]
                    if ready
                    else _WAITING_PROMPTS[field]
                )
                if field == "sapi" and current is None and len(values) == 1:
                    widget.value = values[0]
            selected[field] = self._value(widget)

    def on_select_changed(self, event: Select.Changed) -> None:
        if self._updating:
            return
        widget_id = event.select.id
        axis_ids = [item[1] for item in _AXES]
        if widget_id in axis_ids:
            index = axis_ids.index(widget_id)
            self._clear(*(item[1] for item in _AXES[index + 1:]))
            self._sync_axis_options()
        elif widget_id == "verifier-mode":
            http = self._value(event.select) == "http"
            self.query_one("#verify-path", Input).disabled = not http
            self.query_one("#verify-text", Input).disabled = not http
        self._refresh()

    def on_input_changed(self, _event: Input.Changed) -> None:
        self._refresh()

    def _run_draft(self) -> RunDraft:
        workers_text = self.query_one("#workers", Input).value.strip()
        try:
            workers = int(workers_text) if workers_text else None
        except ValueError as exc:
            raise PlanError("MaxRequestWorkers override must be a positive integer") from exc
        mode = self._value(self.query_one("#verifier-mode", Select)) or "none"
        return RunDraft(
            target_url=self.query_one("#target-url", Input).value,
            workers_override=workers,
            command=self.query_one("#command", Input).value,
            verifier_mode=VerifierMode(mode),
            verify_path=self.query_one("#verify-path", Input).value,
            verify_text=self.query_one("#verify-text", Input).value,
            evidence_dir=self.query_one("#evidence-dir", Input).value,
        )

    def _configure_workers(self, resolution: ProfileResolution | None) -> str:
        widget = self.query_one("#workers", Input)
        track = resolution.track if resolution is not None else None
        if track is None:
            widget.disabled = True
            widget.placeholder = "select target contract"
            return "—"
        sapi = SAPI_BY_ID[track.sapi]
        if not sapi.uses_max_request_workers:
            with widget.prevent(Input.Changed):
                widget.value = ""
            widget.disabled = True
            widget.placeholder = "not applicable"
            return "not applicable"
        widget.disabled = False
        widget.placeholder = (
            f"{track.default_workers} · profile default"
            if track.default_workers is not None
            else "override required"
        )
        override = widget.value.strip()
        if override:
            return f"{override} (override)"
        if track.default_workers is not None:
            return f"{track.default_workers} (profile default)"
        return "override required"

    def _refresh(self) -> None:
        selection = self._selection()
        summary = self.query_one("#summary", Static)
        run = self.query_one("#run", Button)
        review = self.query_one("#review", Button)
        reset = self.query_one("#reset", Button)
        hint = self.query_one("#run-hint", Static)
        preview = self.query_one("#command-preview", TextArea)
        for status in QualificationStatus:
            summary.remove_class(status.value)

        self.resolution = None
        self.plan = None
        if not selection.complete:
            self._configure_workers(None)
            selected = sum(value is not None for value in (
                selection.php_release,
                selection.sapi,
                selection.runtime_product,
                selection.architecture,
                selection.ini_contract_id,
            ))
            sapi_label = SAPI_BY_ID[selection.sapi].label if selection.sapi else "—"
            summary.update(
                f"STATUS        SELECT TARGET\n"
                f"PROGRESS      {selected}/5 axes\n"
                f"SAPI          {sapi_label}\n\n"
                "Complete the selectors in order."
            )
            run.disabled = True
            review.label = "Profile required"
            review.disabled = True
            reset.disabled = self._run_active
            preview.text = "# select an exact target contract"
            if not self._run_active:
                hint.update("Complete an exact target contract and run draft.")
            return

        self.resolution = self.catalog.resolve(
            php_release=selection.php_release or "",
            runtime_product=selection.runtime_product or "",
            architecture=selection.architecture or "",
            ini_contract_id=selection.ini_contract_id or "",
            sapi=selection.sapi or "",
        )
        resolution = self.resolution
        workers_summary = self._configure_workers(resolution)
        summary.add_class(resolution.status.value)
        product_label = _axis_label("runtime_product", selection.runtime_product or "")
        architecture_label = _axis_label("architecture", selection.architecture or "")
        sapi = SAPI_BY_ID[selection.sapi or ""]
        alias = mutable_image_alias(
            selection.php_release or "",
            selection.runtime_product or "",
        )
        profile_id = resolution.profile.profile_id if resolution.profile else "— disposition"
        code_build = resolution.profile.php_code_build_id if resolution.profile else "—"
        runtime_bundle = resolution.profile.runtime_bundle_id if resolution.profile else "—"
        resolution_detail = (
            "" if resolution.profile is not None else f"\n\n{resolution.reason}"
        )
        summary.update(
            f"STATUS        {resolution.status.value.upper()}\n"
            f"PHP           {selection.php_release}\n"
            f"RUNTIME       {product_label}\n"
            f"PLATFORM      {architecture_label}\n"
            f"INI           {selection.ini_contract_id}\n"
            f"SAPI          {sapi.label}\n"
            f"WORKERS       {workers_summary}\n"
            f"TAG HINT      {alias}  (mutable)\n\n"
            f"PROFILE       {profile_id}\n"
            f"PHP BUILD     {code_build}\n"
            f"BUNDLE        {runtime_bundle}"
            f"{resolution_detail}"
        )

        try:
            self.plan = freeze_run_plan(
                resolution,
                self._run_draft(),
                allow_candidate=True,
            )
        except PlanError as exc:
            run.disabled = True
            review.disabled = True
            review.label = (
                "Unavailable"
                if resolution.profile is None
                else "Complete run draft"
            )
            reset.disabled = self._run_active
            preview.text = f"# unavailable: {exc}"
            if not self._run_active:
                hint.update("Resolve the run draft before starting.")
        else:
            run.disabled = self._run_active
            review.disabled = self._run_active
            reset.disabled = self._run_active
            review.label = (
                "Copy candidate CLI"
                if resolution.status is QualificationStatus.CANDIDATE
                else "Copy run CLI"
            )
            preview.text = self.plan.shell_command()
            if not self._run_active:
                hint.update("Ctrl+R runs this frozen plan; Copy keeps the exact CLI.")

    def _emit_run_line(self, line: str) -> None:
        self.run_transcript.append(line)
        modal = self._output_modal
        if modal is not None and modal.is_mounted:
            modal.write_line(line)

    @staticmethod
    async def _terminate_process(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                return
            await process.wait()

    async def _run_subprocess(self, plan: RunPlan, emit: LineSink) -> int:
        process = await asyncio.create_subprocess_exec(
            *execution_argv(plan),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._process = process
        try:
            if process.stdout is None:  # pragma: no cover - PIPE guarantees this
                raise RuntimeError("runner stdout pipe was not created")
            while True:
                raw_line = await process.stdout.readline()
                if not raw_line:
                    break
                emit(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
            return await process.wait()
        except asyncio.CancelledError:
            await self._terminate_process(process)
            raise
        finally:
            if process.returncode is None:
                await self._terminate_process(process)
            if self._process is process:
                self._process = None

    async def _execute_run(self, plan: RunPlan) -> int | None:
        runner = self._runner or self._run_subprocess
        exit_code: int | None = None
        try:
            exit_code = await runner(plan, self._emit_run_line)
        except asyncio.CancelledError:
            self._emit_run_line("[cancelled] run stopped")
            raise
        except Exception as exc:  # keep runner failures visible in the TUI
            self._emit_run_line(f"[runner error] {type(exc).__name__}: {exc}")
        finally:
            self._run_active = False
            self._active_plan = None
            self._run_worker = None
            if self.is_mounted:
                self._refresh()

        hint = self.query_one("#run-hint", Static)
        if exit_code is None:
            hint.update("Run failed before an exit status was available.")
            self.notify("Run failed; inspect RUN OUTPUT.", severity="error")
        elif exit_code == 0:
            hint.update("Run completed · exit 0")
            self.notify("Run completed · exit 0")
        else:
            hint.update(f"Run completed · exit {exit_code}")
            self.notify(f"Run completed · exit {exit_code}", severity="warning")
        modal = self._output_modal
        if modal is not None and modal.is_mounted:
            modal.finish(exit_code)
        return exit_code

    def _output_closed(self, _result: None) -> None:
        if not self._run_active:
            self._output_modal = None

    async def action_run(self) -> None:
        if self._run_active:
            self.notify("A run is already active.", severity="warning")
            return

        # Ctrl+R is a priority binding and can overtake queued Changed messages.
        # Rebuild from the widgets synchronously so the executed snapshot can
        # never be an older otherwise-valid plan (notably Verification=None).
        self._refresh()
        plan = self.plan
        if plan is None:
            self.query_one("#run-hint", Static).update(
                "Complete a valid run draft before pressing Ctrl+R."
            )
            self.notify("No valid frozen run plan.", severity="warning")
            return

        self._run_active = True
        self._active_plan = plan
        self.query_one("#run-hint", Static).update(
            f"Running {plan.profile_id} · Ctrl+Q stops and quits"
        )
        self.query_one("#run", Button).disabled = True
        self.query_one("#review", Button).disabled = True
        self.query_one("#reset", Button).disabled = True

        modal = self._output_modal
        if modal is None or not modal.is_mounted:
            modal = RunOutputModal(plan.profile_id)
            self._output_modal = modal
            try:
                await self.push_screen(modal, callback=self._output_closed)
            except Exception:
                self._output_modal = None
                self._run_active = False
                self._active_plan = None
                self._refresh()
                raise
        modal.prepare(plan.profile_id)
        self.run_transcript.clear()
        self._emit_run_line(f"$ {shlex.join(execution_argv(plan))}")
        self._run_worker = self.run_worker(
            self._execute_run(plan),
            name="exact-run-plan",
            group="run",
            exit_on_error=False,
        )

    def action_review(self) -> None:
        if not self.query_one("#review", Button).disabled and self.plan is not None:
            command = self.plan.shell_command()
            self.copy_to_clipboard(command)
            self.notify("Exact CLI command copied; candidate status is preserved.")

    def action_reset(self) -> None:
        if self._run_active:
            return
        self._updating = True
        try:
            self._clear("php-release", "sapi", "runtime-product", "architecture", "ini-contract")
            self._sync_axis_options()
            for widget_id in (
                "target-url",
                "workers",
                "command",
                "verify-path",
                "verify-text",
                "evidence-dir",
            ):
                widget = self.query_one(f"#{widget_id}", Input)
                with widget.prevent(Input.Changed):
                    widget.value = ""
            verifier = self.query_one("#verifier-mode", Select)
            with verifier.prevent(Select.Changed):
                verifier.value = "none"
            self.query_one("#verify-path", Input).disabled = True
            self.query_one("#verify-text", Input).disabled = True
            self.query_one("#workers", Input).disabled = True
        finally:
            self._updating = False
        self.run_transcript.clear()
        self.query_one("#php-release", Select).focus()
        self._refresh()

    async def action_quit(self) -> None:
        worker = self._run_worker
        process = self._process
        if process is not None and process.returncode is None:
            await self._terminate_process(process)
        if worker is not None and worker.is_running:
            worker.cancel()
            try:
                await worker.wait()
            except WorkerError:
                pass
        self.exit()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            event.stop()
            await self.action_run()
        elif event.button.id == "reset":
            event.stop()
            self.action_reset()
        elif event.button.id == "review":
            event.stop()
            self.action_review()


__all__ = (
    "Php2ShellApp",
    "RunOutputModal",
    "SelectionDraft",
    "execution_argv",
)
