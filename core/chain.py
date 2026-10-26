"""Chain plugin contract and run context."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Protocol

from .evidence import EvidenceWriter
from .profile import ProfileSpec
from .result import RunResult
from .target import Target


@dataclass(frozen=True)
class RunContext:
    target: Target
    evidence: EvidenceWriter


class Chain(Protocol):
    id: str
    summary: str

    def add_arguments(self, parser: argparse.ArgumentParser) -> None: ...

    def describe_profile(self, profile: ProfileSpec[object]) -> dict[str, object]: ...

    def run(
        self,
        context: RunContext,
        profile: ProfileSpec[object],
        args: argparse.Namespace,
    ) -> RunResult: ...
