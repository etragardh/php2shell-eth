"""Manifest-driven target catalog used by selection frontends.

Every selectable track comes from either an immutable profile leaf or an
explicit non-runnable disposition.  There is no separately maintained matrix
of aspirational tracks, so adding or removing a manifest changes the selector
surface without a second registration step.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable


SAPI_ID = "apache2handler-prefork"


class QualificationStatus(str, Enum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    RETIRED = "retired"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"

    @property
    def runnable(self) -> bool:
        return self is QualificationStatus.SUPPORTED


@dataclass(frozen=True, order=True)
class ReleaseSpec:
    branch: str
    release: str
    label: str


@dataclass(frozen=True, order=True)
class RuntimeProductSpec:
    id: str
    label: str
    short_label: str
    description: str


@dataclass(frozen=True, order=True)
class ArchitectureSpec:
    id: str
    oci_platform: str
    label: str
    aliases: tuple[str, ...]


@dataclass(frozen=True, order=True)
class IniContractSpec:
    id: str
    label: str
    description: str


@dataclass(frozen=True, order=True)
class SapiSpec:
    id: str
    label: str
    php_sapi_name: str
    process_model: str
    uses_max_request_workers: bool
    description: str


RELEASES = (
    ReleaseSpec("8.3", "8.3.35", "PHP 8.3 · 8.3.35"),
    ReleaseSpec("8.4", "8.4.26", "PHP 8.4 · 8.4.26"),
)

RUNTIME_PRODUCTS = (
    RuntimeProductSpec(
        "docker-library/php",
        "Docker Library PHP",
        "PHP",
        "The official docker-library/php Apache image lineage.",
    ),
    RuntimeProductSpec(
        "docker-library/wordpress",
        "Docker Library WordPress",
        "WordPress",
        "The official docker-library/wordpress Apache image lineage.",
    ),
)

ARCHITECTURES = (
    ArchitectureSpec("amd64", "linux/amd64", "amd64", ("x86_64",)),
    ArchitectureSpec("arm64", "linux/arm64", "arm64", ("aarch64",)),
)

SAPI_SPECS = (
    SapiSpec(
        SAPI_ID,
        "Apache module · prefork",
        "apache2handler",
        "apache-mpm-prefork",
        True,
        "PHP apache2handler hosted by Apache mpm_prefork.",
    ),
    SapiSpec(
        "cli",
        "PHP CLI",
        "cli",
        "single-process",
        False,
        "PHP CLI execution; distinct from the cli-server and web SAPIs.",
    ),
)
SAPI_BY_ID = {item.id: item for item in SAPI_SPECS}

INI_CONTRACTS = {
    "upstream-production": IniContractSpec(
        "upstream-production",
        "Upstream production",
        "The matching upstream php.ini-production plus captured conf.d fragments.",
    ),
    "no-main-ini": IniContractSpec(
        "no-main-ini",
        "Image default · no main ini",
        "No loaded main php.ini; compiled defaults and conf.d still apply.",
    ),
    "wordpress-default": IniContractSpec(
        "wordpress-default",
        "WordPress image default",
        "The exact effective defaults and extensions of the WordPress runtime bundle.",
    ),
    "wordpress-upstream-production": IniContractSpec(
        "wordpress-upstream-production",
        "WordPress + upstream production",
        "The WordPress runtime bundle with the matching upstream production ini.",
    ),
}

PRODUCT_INI_CONTRACTS = {
    "docker-library/php": ("upstream-production", "no-main-ini"),
    "docker-library/wordpress": (
        "wordpress-default",
        "wordpress-upstream-production",
    ),
}


@dataclass(frozen=True, order=True)
class TargetTrack:
    """One exact selectable target contract."""

    php_release: str
    sapi: str
    runtime_product: str
    architecture: str
    ini_contract_id: str
    default_workers: int | None = None
    worker_default_source: str | None = None

    def validate(self) -> None:
        axes = (
            ("php_release", self.php_release),
            ("sapi", self.sapi),
            ("runtime_product", self.runtime_product),
            ("architecture", self.architecture),
            ("ini_contract_id", self.ini_contract_id),
        )
        for label, value in axes:
            if (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or any(ord(character) < 32 for character in value)
            ):
                raise ValueError(f"invalid target-track {label}: {value!r}")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", self.php_release):
            raise ValueError(f"invalid numeric PHP release: {self.php_release!r}")
        try:
            sapi = SAPI_BY_ID[self.sapi]
        except KeyError as exc:
            raise ValueError(f"unknown SAPI contract: {self.sapi}") from exc
        if self.runtime_product not in {item.id for item in RUNTIME_PRODUCTS}:
            raise ValueError(f"unknown runtime product: {self.runtime_product}")
        if self.architecture not in {item.id for item in ARCHITECTURES}:
            raise ValueError(f"unknown target architecture: {self.architecture}")
        if self.ini_contract_id not in PRODUCT_INI_CONTRACTS[self.runtime_product]:
            raise ValueError(
                "ini contract does not belong to runtime product: "
                f"{self.ini_contract_id}/{self.runtime_product}"
            )
        if self.default_workers is not None and (
            isinstance(self.default_workers, bool) or self.default_workers < 1
        ):
            raise ValueError(f"invalid worker default for track: {self.id}")
        if (self.default_workers is None) != (self.worker_default_source is None):
            raise ValueError(f"worker default/source mismatch for track: {self.id}")
        if self.worker_default_source is not None and not self.worker_default_source.strip():
            raise ValueError(f"empty worker-default provenance for track: {self.id}")
        if not sapi.uses_max_request_workers and self.default_workers is not None:
            raise ValueError(f"workerless SAPI has worker default: {self.id}")

    @property
    def id(self) -> str:
        return "/".join((
            self.php_release,
            self.sapi,
            self.ini_contract_id,
            self.runtime_product,
            self.architecture,
        ))

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.php_release,
            self.sapi,
            self.runtime_product,
            self.architecture,
            self.ini_contract_id,
        )


@dataclass(frozen=True)
class QualificationRecord:
    """Evidence binding for one immutable manifest revision."""

    bound_manifest_digest: str
    chain_revision: str
    scheduler_revision: str
    campaign_id: str
    attempts: int
    successes: int
    run_record_sha256: str

    def validate(self) -> None:
        if not self.bound_manifest_digest.startswith("sha256:"):
            raise ValueError("qualification has no bound manifest digest")
        if not self.chain_revision or not self.scheduler_revision or not self.campaign_id:
            raise ValueError("qualification revision identity is incomplete")
        if self.attempts < 1 or not (0 <= self.successes <= self.attempts):
            raise ValueError("qualification attempt counts are invalid")
        if re.fullmatch(r"[0-9a-f]{64}", self.run_record_sha256) is None:
            raise ValueError("qualification run record SHA-256 is invalid")


@dataclass(frozen=True)
class ProfileLeaf:
    """An immutable target profile with independently bound qualification."""

    track: TargetTrack
    profile_id: str
    profile_digest: str
    php_code_build_id: str
    runtime_bundle_id: str
    platform_manifest_digest: str
    status: QualificationStatus
    qualification_summary: str
    qualification: QualificationRecord | None = None

    def validate(self) -> None:
        self.track.validate()
        if not self.profile_id or not _is_sha256(self.profile_digest):
            raise ValueError("profile leaf identity is incomplete")
        if not self.php_code_build_id or not self.runtime_bundle_id:
            raise ValueError("profile leaf artifact identity is incomplete")
        if not _is_sha256(self.platform_manifest_digest):
            raise ValueError("OCI profile leaf needs a platform manifest digest")
        if self.status not in {
            QualificationStatus.CANDIDATE,
            QualificationStatus.SUPPORTED,
            QualificationStatus.RETIRED,
        }:
            raise ValueError(f"invalid profile-leaf status: {self.status.value}")
        if not self.qualification_summary.strip():
            raise ValueError("profile leaf qualification summary is empty")
        if self.qualification is not None:
            self.qualification.validate()
            if self.qualification.bound_manifest_digest != self.profile_digest:
                raise ValueError("qualification is bound to a different manifest")


@dataclass(frozen=True)
class TrackDisposition:
    """An explicitly catalogued track that cannot resolve to a profile."""

    track: TargetTrack
    status: QualificationStatus
    reason: str
    provenance: str

    def validate(self) -> None:
        self.track.validate()
        if self.status not in {
            QualificationStatus.UNAVAILABLE,
            QualificationStatus.REJECTED,
        }:
            raise ValueError(f"invalid track disposition status: {self.status.value}")
        if not self.reason.strip() or not self.provenance.strip():
            raise ValueError("track disposition reason/provenance is incomplete")


@dataclass(frozen=True)
class ProfileResolution:
    track: TargetTrack | None
    profile: ProfileLeaf | None
    status: QualificationStatus
    reason: str

    @property
    def runnable(self) -> bool:
        return self.profile is not None and self.status.runnable


_TRACK_AXES = (
    "php_release",
    "sapi",
    "runtime_product",
    "architecture",
    "ini_contract_id",
)


def _is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value))


def numeric_version_key(value: str) -> tuple[int, ...]:
    """Sort dotted numeric releases numerically, never lexicographically."""
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value):
        raise ValueError(f"version is not dotted numeric text: {value!r}")
    return tuple(int(part) for part in value.split("."))


def _track_sort_key(track: TargetTrack) -> tuple[object, ...]:
    return (
        numeric_version_key(track.php_release),
        track.sapi,
        track.runtime_product,
        track.architecture,
        track.ini_contract_id,
    )


class ProfileCatalog:
    """Exact manifest/disposition resolver with no nearest-profile fallback."""

    def __init__(
        self,
        profiles: Iterable[ProfileLeaf] = (),
        dispositions: Iterable[TrackDisposition] = (),
    ) -> None:
        profile_items = tuple(profiles)
        disposition_items = tuple(dispositions)
        self._profiles: dict[tuple[str, ...], ProfileLeaf] = {}
        self._dispositions: dict[tuple[str, ...], TrackDisposition] = {}
        self._tracks: dict[tuple[str, ...], TargetTrack] = {}
        profile_ids: set[str] = set()
        for profile in profile_items:
            profile.validate()
            if profile.profile_id in profile_ids:
                raise ValueError(f"duplicate profile id: {profile.profile_id}")
            if profile.track.key in self._profiles:
                raise ValueError(f"duplicate profile for track: {profile.track.id}")
            profile_ids.add(profile.profile_id)
            self._profiles[profile.track.key] = profile
            self._tracks[profile.track.key] = profile.track
        for disposition in disposition_items:
            disposition.validate()
            track_key = disposition.track.key
            if track_key in self._tracks:
                raise ValueError(
                    f"profile/disposition track collision: {disposition.track.id}"
                )
            self._dispositions[track_key] = disposition
            self._tracks[track_key] = disposition.track

    @property
    def tracks(self) -> tuple[TargetTrack, ...]:
        return tuple(sorted(self._tracks.values(), key=_track_sort_key))

    @property
    def profiles(self) -> tuple[ProfileLeaf, ...]:
        return tuple(sorted(self._profiles.values(), key=lambda item: item.profile_id))

    @property
    def dispositions(self) -> tuple[TrackDisposition, ...]:
        return tuple(sorted(
            self._dispositions.values(),
            key=lambda item: _track_sort_key(item.track),
        ))

    def matching_tracks(self, **filters: str | None) -> tuple[TargetTrack, ...]:
        unknown = set(filters) - set(_TRACK_AXES)
        if unknown:
            raise ValueError(f"unknown target-track filter(s): {', '.join(sorted(unknown))}")
        active = {
            field: value for field, value in filters.items()
            if value is not None
        }
        return tuple(
            track for track in self.tracks
            if all(getattr(track, field) == value for field, value in active.items())
        )

    def values(self, field: str, **filters: str | None) -> tuple[str, ...]:
        if field not in _TRACK_AXES:
            raise ValueError(f"unknown target-track field: {field}")
        values = {getattr(track, field) for track in self.matching_tracks(**filters)}
        if field == "php_release":
            return tuple(sorted(values, key=numeric_version_key))
        return tuple(sorted(values))

    def resolve(
        self,
        *,
        php_release: str,
        runtime_product: str,
        architecture: str,
        ini_contract_id: str,
        sapi: str,
    ) -> ProfileResolution:
        wanted = TargetTrack(
            php_release,
            sapi,
            runtime_product,
            architecture,
            ini_contract_id,
        )
        track = self._tracks.get(wanted.key)
        if track is None:
            return ProfileResolution(
                None,
                None,
                QualificationStatus.UNAVAILABLE,
                "That exact combination is outside the explicit target catalog.",
            )
        profile = self._profiles.get(track.key)
        if profile is not None:
            return ProfileResolution(
                track,
                profile,
                profile.status,
                profile.qualification_summary,
            )
        disposition = self._dispositions[track.key]
        return ProfileResolution(track, None, disposition.status, disposition.reason)


def ini_contracts_for(runtime_product: str) -> tuple[IniContractSpec, ...]:
    try:
        return tuple(INI_CONTRACTS[item] for item in PRODUCT_INI_CONTRACTS[runtime_product])
    except KeyError as exc:
        raise ValueError(f"unknown runtime product: {runtime_product}") from exc


def mutable_image_alias(php_release: str, runtime_product: str) -> str:
    numeric_version_key(php_release)
    branch = ".".join(php_release.split(".")[:2])
    if runtime_product == "docker-library/php":
        return f"php:{php_release}-apache"
    if runtime_product == "docker-library/wordpress":
        return f"wordpress:php{branch}-apache"
    return f"{runtime_product}:{php_release}"


__all__ = (
    "ARCHITECTURES",
    "INI_CONTRACTS",
    "PRODUCT_INI_CONTRACTS",
    "ProfileCatalog",
    "ProfileLeaf",
    "ProfileResolution",
    "QualificationRecord",
    "QualificationStatus",
    "RELEASES",
    "RUNTIME_PRODUCTS",
    "SAPI_BY_ID",
    "SAPI_SPECS",
    "SAPI_ID",
    "TargetTrack",
    "TrackDisposition",
    "ini_contracts_for",
    "mutable_image_alias",
    "numeric_version_key",
)
