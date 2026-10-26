"""Common profile envelope; calibration payloads stay chain-specific."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar


CalibrationT = TypeVar("CalibrationT")


@dataclass(frozen=True)
class SchedulerBinding:
    """Scheduler contract frozen into an executable profile manifest."""

    id: str
    default_workers: int | None = None

    def validate(self) -> None:
        if not self.id:
            raise ValueError("profile scheduler id is empty")
        if self.default_workers is not None and self.default_workers < 1:
            raise ValueError("profile scheduler worker default must be positive")


@dataclass(frozen=True)
class TargetFingerprint:
    architecture: str
    php_version: str
    sapi: str
    image: str
    image_id: str
    php_ini_sha256: str
    binary_sha256: str
    extension_configs: tuple[str, ...]
    ini_settings: tuple[tuple[str, str], ...]

    def validate(self) -> None:
        if not self.architecture or not self.php_version or not self.sapi:
            raise ValueError("profile target fingerprint is incomplete")
        names = [name for name, _ in self.ini_settings]
        if len(names) != len(set(names)):
            raise ValueError("profile target fingerprint has duplicate ini directives")


@dataclass(frozen=True)
class ProfileSpec(Generic[CalibrationT]):
    id: str
    chain_id: str
    target: TargetFingerprint
    calibration: CalibrationT
    provenance: str
    requirements: tuple[str, ...] = ()
    scheduler: SchedulerBinding | None = None

    def validate(self) -> None:
        if "/" not in self.id:
            raise ValueError(f"profile id must be qualified: {self.id}")
        if not self.id.startswith(self.chain_id + "/"):
            raise ValueError(f"profile id {self.id!r} does not match chain {self.chain_id!r}")
        short_name = self.id[len(self.chain_id) + 1:]
        if not short_name:
            raise ValueError(f"profile id {self.id!r} has no manifest name")
        self.target.validate()
        if self.scheduler is not None:
            self.scheduler.validate()
        validate = getattr(self.calibration, "validate", None)
        if callable(validate):
            validate()


__all__ = ("ProfileSpec", "SchedulerBinding", "TargetFingerprint")
