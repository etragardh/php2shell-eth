"""Structured outcomes shared by all exploit chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    SUCCESS = "success"
    TRANSIENT_MISS = "transient_miss"
    PROFILE_MISMATCH = "profile_mismatch"
    REQUIREMENT_MISSING = "requirement_missing"
    UNSAFE_TO_CONTINUE = "unsafe_to_continue"
    TRANSPORT_ERROR = "transport_error"
    UNCONFIRMED = "unconfirmed"


EXIT_CODES = {
    Outcome.SUCCESS: 0,
    Outcome.TRANSIENT_MISS: 2,
    Outcome.PROFILE_MISMATCH: 3,
    Outcome.REQUIREMENT_MISSING: 3,
    Outcome.UNSAFE_TO_CONTINUE: 5,
    Outcome.TRANSPORT_ERROR: 6,
    Outcome.UNCONFIRMED: 4,
}


@dataclass(frozen=True)
class StageResult:
    name: str
    outcome: Outcome
    reason: str = ""
    values: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunResult:
    chain_id: str
    profile_id: str
    outcome: Outcome
    reason: str = ""
    stages: tuple[StageResult, ...] = ()

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.outcome]
