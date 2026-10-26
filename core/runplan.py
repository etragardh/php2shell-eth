"""UI-neutral v2 run planning.

Planning is local and side-effect free.  Network execution may consume only a
frozen :class:`RunPlan`, never live TUI widget state.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import shlex

from core.catalog import QualificationStatus, SAPI_BY_ID, ProfileResolution
from core.target import Target, validate_http_path


class PlanError(ValueError):
    pass


class VerifierMode(str, Enum):
    NONE = "none"
    HTTP = "http"


class WorkerSource(str, Enum):
    PROFILE_DEFAULT = "profile_default"
    OVERRIDE = "override"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class VerifierSpec:
    mode: VerifierMode
    path: str | None = None
    expected_text: str | None = None


@dataclass(frozen=True)
class RunDraft:
    target_url: str
    workers_override: int | None
    command: str
    verifier_mode: VerifierMode = VerifierMode.NONE
    verify_path: str = ""
    verify_text: str = ""
    evidence_dir: str = ""


@dataclass(frozen=True)
class WorkerPlan:
    effective: int | None
    source: WorkerSource
    default_source: str | None = None


@dataclass(frozen=True)
class RunPlan:
    profile_id: str
    profile_digest: str
    target_url: str
    workers: WorkerPlan
    command: bytes
    verifier: VerifierSpec
    evidence_dir: Path | None

    def argv(self, executable: str = "./php2shell-eth.py") -> tuple[str, ...]:
        values = [
            executable,
            "run",
            self.target_url,
            "--profile",
            self.profile_id,
            "--profile-digest",
            self.profile_digest,
        ]
        if self.workers.source is WorkerSource.OVERRIDE:
            values.extend(("--workers", str(self.workers.effective)))
        values.extend(("--cmd", self.command.decode("utf-8")))
        if self.verifier.mode is VerifierMode.HTTP:
            values.extend((
                "--verify-path",
                self.verifier.path or "",
                "--verify-text",
                self.verifier.expected_text or "",
            ))
        if self.evidence_dir is not None:
            values.extend(("--evidence-dir", str(self.evidence_dir)))
        return tuple(values)

    def shell_command(self, executable: str = "./php2shell-eth.py") -> str:
        return shlex.join(self.argv(executable))


def freeze_run_plan(
    resolution: ProfileResolution,
    draft: RunDraft,
    *,
    allow_candidate: bool = False,
) -> RunPlan:
    candidate_allowed = (
        allow_candidate
        and resolution.status is QualificationStatus.CANDIDATE
        and resolution.profile is not None
    )
    if (not resolution.runnable and not candidate_allowed) or resolution.profile is None:
        raise PlanError("the selected target has no supported, qualified profile")

    target_url = draft.target_url.strip()
    if not target_url:
        raise PlanError("target URL is required")
    try:
        target = Target.parse(target_url)
    except ValueError as exc:
        raise PlanError(str(exc)) from exc

    track = resolution.profile.track
    if (
        resolution.profile.profile_id.startswith("modphp-pinned-v1/")
        and target.scheme != "http"
    ):
        raise PlanError("the selected pinned profile requires direct HTTP")

    sapi = SAPI_BY_ID[track.sapi]
    if sapi.uses_max_request_workers:
        if draft.workers_override is not None:
            if draft.workers_override < 1:
                raise PlanError("MaxRequestWorkers override must be a positive integer")
            workers = WorkerPlan(draft.workers_override, WorkerSource.OVERRIDE)
        elif track.default_workers is not None:
            workers = WorkerPlan(
                track.default_workers,
                WorkerSource.PROFILE_DEFAULT,
                track.worker_default_source,
            )
        else:
            raise PlanError("this target needs a MaxRequestWorkers override")
    else:
        if draft.workers_override is not None:
            raise PlanError(f"{sapi.label} does not accept a worker override")
        workers = WorkerPlan(None, WorkerSource.NOT_APPLICABLE)

    command_text = draft.command
    if command_text == "":
        raise PlanError("command is required")
    command = command_text.encode("utf-8")
    if b"\0" in command:
        raise PlanError("command cannot contain NUL")

    if draft.verifier_mode is VerifierMode.HTTP:
        path = draft.verify_path.strip()
        expected = draft.verify_text
        try:
            validate_http_path(path, label="HTTP verification path")
        except ValueError as exc:
            raise PlanError(str(exc)) from exc
        if not expected:
            raise PlanError("HTTP verification text is required")
        verifier = VerifierSpec(VerifierMode.HTTP, path, expected)
    else:
        verifier = VerifierSpec(VerifierMode.NONE)

    evidence_dir = Path(draft.evidence_dir).expanduser() if draft.evidence_dir.strip() else None
    return RunPlan(
        resolution.profile.profile_id,
        resolution.profile.profile_digest,
        target.url,
        workers,
        command,
        verifier,
        evidence_dir,
    )


__all__ = (
    "PlanError",
    "RunDraft",
    "RunPlan",
    "VerifierMode",
    "VerifierSpec",
    "WorkerPlan",
    "WorkerSource",
    "freeze_run_plan",
)
