"""Strict loader for self-contained pinned profile manifests."""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, TypeVar

from chains.modphp_pinned.model import (
    CHAIN_ID,
    SCHEDULER_ID,
    ModPhpPinnedCalibration,
)
from chains.modphp_pinned.schema import (
    A1Profile,
    A2Profile,
    AbiLayout,
    AllocatorLayout,
    B1Profile,
    B1ReleasePlan,
    B2Profile,
    HeapOffsets,
    SymbolOffsets,
)
from core.catalog import (
    ARCHITECTURES,
    PRODUCT_INI_CONTRACTS,
    ProfileLeaf,
    QualificationRecord,
    QualificationStatus,
    TargetTrack,
    mutable_image_alias,
)
from core.profile import ProfileSpec, SchedulerBinding, TargetFingerprint


T = TypeVar("T")


_PRODUCT_REPOSITORIES = {
    "docker-library/php": "docker.io/library/php",
    "docker-library/wordpress": "docker.io/library/wordpress",
}


@dataclass(frozen=True)
class LoadedManifest:
    profile: ProfileSpec[ModPhpPinnedCalibration]
    leaf: ProfileLeaf


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _strict_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} fields differ: missing={missing}, extra={extra}")


def _record(
    cls: type[T],
    value: Any,
    label: str,
    *,
    tuple_fields: tuple[str, ...] = (),
) -> T:
    data = _mapping(value, label)
    expected = {field.name for field in fields(cls)}
    _strict_keys(data, expected, label)
    converted = dict(data)
    for name in tuple_fields:
        item = converted[name]
        if not isinstance(item, list):
            raise ValueError(f"{label}.{name} must be a JSON array")
        converted[name] = tuple(item)
    return cls(**converted)


def _bytes(value: Any, label: str) -> bytes:
    data = _mapping(value, label)
    _strict_keys(data, {"$bytes"}, label)
    encoded = data["$bytes"]
    if not isinstance(encoded, str):
        raise ValueError(f"{label} byte encoding must be hexadecimal text")
    try:
        return bytes.fromhex(encoded)
    except ValueError as exc:
        raise ValueError(f"{label} byte encoding is invalid") from exc


def _sha256(value: Any, label: str, *, prefixed: bool) -> str:
    pattern = r"sha256:[0-9a-f]{64}" if prefixed else r"[0-9a-f]{64}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{label} is not a canonical SHA-256 value")
    return value


def _manifest_digest(profile: Any, identity: Any) -> str:
    signed = {
        "schema_version": 1,
        "profile": profile,
        "identity": identity,
    }
    payload = json.dumps(
        signed,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _target(value: Any) -> TargetFingerprint:
    data = _mapping(value, "profile.target")
    _strict_keys(data, {field.name for field in fields(TargetFingerprint)}, "profile.target")
    extension_configs = data["extension_configs"]
    ini_settings = data["ini_settings"]
    if not isinstance(extension_configs, list) or not isinstance(ini_settings, list):
        raise ValueError("target extensions and ini settings must be arrays")
    if not all(isinstance(item, list) and len(item) == 2 for item in ini_settings):
        raise ValueError("target ini settings must be name/value pairs")
    return TargetFingerprint(
        architecture=data["architecture"],
        php_version=data["php_version"],
        sapi=data["sapi"],
        image=data["image"],
        image_id=data["image_id"],
        php_ini_sha256=data["php_ini_sha256"],
        binary_sha256=data["binary_sha256"],
        extension_configs=tuple(extension_configs),
        ini_settings=tuple(tuple(item) for item in ini_settings),
    )


def _calibration(value: Any) -> ModPhpPinnedCalibration:
    data = _mapping(value, "profile.calibration")
    _strict_keys(
        data,
        {"abi", "allocator", "symbols", "heap", "a1", "b1", "a2", "b2"},
        "profile.calibration",
    )
    b1_data = dict(_mapping(data["b1"], "profile.calibration.b1"))
    release = b1_data.get("release_sprays")
    if isinstance(release, dict):
        b1_data["release_sprays"] = _record(
            B1ReleasePlan,
            release,
            "profile.calibration.b1.release_sprays",
            tuple_fields=("spray_indices", "post_release_pages"),
        )
    elif not isinstance(release, bool):
        raise ValueError("B1 release_sprays must be boolean or a release plan")
    marker = b1_data.get("marker")
    b1_data["marker"] = _bytes(marker, "profile.calibration.b1.marker")
    return ModPhpPinnedCalibration(
        abi=_record(AbiLayout, data["abi"], "profile.calibration.abi"),
        allocator=_record(
            AllocatorLayout, data["allocator"], "profile.calibration.allocator",
        ),
        symbols=_record(
            SymbolOffsets, data["symbols"], "profile.calibration.symbols",
        ),
        heap=_record(HeapOffsets, data["heap"], "profile.calibration.heap"),
        a1=_record(
            A1Profile,
            data["a1"],
            "profile.calibration.a1",
            tuple_fields=("calibration_file_candidates",),
        ),
        b1=_record(
            B1Profile,
            b1_data,
            "profile.calibration.b1",
            tuple_fields=("page_spec",),
        ),
        a2=_record(A2Profile, data["a2"], "profile.calibration.a2"),
        b2=_record(B2Profile, data["b2"], "profile.calibration.b2"),
    )


def _profile(value: Any) -> ProfileSpec[ModPhpPinnedCalibration]:
    data = _mapping(value, "profile")
    _strict_keys(
        data,
        {"id", "chain_id", "target", "calibration", "provenance", "requirements", "scheduler"},
        "profile",
    )
    scheduler = _record(
        SchedulerBinding, data["scheduler"], "profile.scheduler",
    )
    requirements = data["requirements"]
    if not isinstance(requirements, list) or not all(
        isinstance(item, str) for item in requirements
    ):
        raise ValueError("profile.requirements must be a string array")
    profile = ProfileSpec(
        id=data["id"],
        chain_id=data["chain_id"],
        target=_target(data["target"]),
        calibration=_calibration(data["calibration"]),
        provenance=data["provenance"],
        requirements=tuple(requirements),
        scheduler=scheduler,
    )
    profile.validate()
    if profile.chain_id != CHAIN_ID:
        raise ValueError(f"manifest belongs to inactive chain {profile.chain_id}")
    return profile


def load_manifest(path: Path) -> LoadedManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load profile manifest {path.name}: {exc}") from exc
    data = _mapping(raw, path.name)
    _strict_keys(
        data,
        {"schema_version", "profile", "identity", "manifest_digest", "qualification"},
        path.name,
    )
    if data["schema_version"] != 1:
        raise ValueError(f"{path.name}: unsupported schema version")
    expected_digest = _manifest_digest(data["profile"], data["identity"])
    if data["manifest_digest"] != expected_digest:
        raise ValueError(f"{path.name}: manifest digest mismatch")

    profile = _profile(data["profile"])
    identity = _mapping(data["identity"], "identity")
    _strict_keys(
        identity,
        {"track", "php_code_build_id", "runtime_bundle_id", "platform_manifest_digest"},
        "identity",
    )
    track = _record(TargetTrack, identity["track"], "identity.track")
    track.validate()
    qualification_data = _mapping(data["qualification"], "qualification")
    _strict_keys(
        qualification_data,
        {
            "status", "summary", "bound_manifest_digest", "chain_revision",
            "scheduler_revision", "campaign_id", "attempts", "successes",
            "run_record_sha256",
        },
        "qualification",
    )
    try:
        status = QualificationStatus(qualification_data["status"])
    except ValueError as exc:
        raise ValueError(f"{path.name}: unknown qualification status") from exc
    qualification = QualificationRecord(
        bound_manifest_digest=qualification_data["bound_manifest_digest"],
        chain_revision=qualification_data["chain_revision"],
        scheduler_revision=qualification_data["scheduler_revision"],
        campaign_id=qualification_data["campaign_id"],
        attempts=qualification_data["attempts"],
        successes=qualification_data["successes"],
        run_record_sha256=qualification_data["run_record_sha256"],
    )
    leaf = ProfileLeaf(
        track=track,
        profile_id=profile.id,
        profile_digest=expected_digest,
        php_code_build_id=identity["php_code_build_id"],
        runtime_bundle_id=identity["runtime_bundle_id"],
        platform_manifest_digest=identity["platform_manifest_digest"],
        status=status,
        qualification_summary=qualification_data["summary"],
        qualification=qualification,
    )

    arch = {alias: item.id for item in ARCHITECTURES for alias in item.aliases}.get(
        profile.target.architecture
    )
    if arch != track.architecture:
        raise ValueError(f"{path.name}: profile/track architecture mismatch")
    if profile.target.php_version != track.php_release:
        raise ValueError(f"{path.name}: profile/track release mismatch")
    if profile.target.sapi != "apache2handler/prefork" or track.sapi != "apache2handler-prefork":
        raise ValueError(f"{path.name}: profile/track SAPI mismatch")
    try:
        repository = _PRODUCT_REPOSITORIES[track.runtime_product]
        product_ini_contracts = PRODUCT_INI_CONTRACTS[track.runtime_product]
    except KeyError as exc:
        raise ValueError(f"{path.name}: unsupported runtime product binding") from exc
    if track.ini_contract_id not in product_ini_contracts:
        raise ValueError(f"{path.name}: ini contract does not belong to runtime product")
    if profile.target.image != mutable_image_alias(
        track.php_release, track.runtime_product,
    ):
        raise ValueError(f"{path.name}: mutable image hint mismatch")
    no_main_ini = track.ini_contract_id in {"no-main-ini", "wordpress-default"}
    production_ini = track.ini_contract_id in {
        "upstream-production", "wordpress-upstream-production",
    }
    if no_main_ini:
        if profile.target.php_ini_sha256 != "none":
            raise ValueError(f"{path.name}: no-main-ini fingerprint mismatch")
    elif production_ini:
        if profile.target.php_ini_sha256 == "none":
            raise ValueError(f"{path.name}: production ini fingerprint missing")
        _sha256(profile.target.php_ini_sha256, "profile.target.php_ini_sha256", prefixed=False)
    else:
        raise ValueError(f"{path.name}: unsupported ini contract")
    if profile.scheduler is None:
        raise ValueError(f"{path.name}: scheduler binding missing")
    if profile.scheduler.id != SCHEDULER_ID:
        raise ValueError(f"{path.name}: scheduler is incompatible with active chain")
    if profile.scheduler.default_workers != track.default_workers:
        raise ValueError(f"{path.name}: scheduler/track worker default mismatch")
    if qualification.scheduler_revision != profile.scheduler.id:
        raise ValueError(f"{path.name}: qualification scheduler mismatch")
    if not qualification.chain_revision.startswith(profile.chain_id + "/"):
        raise ValueError(f"{path.name}: qualification chain revision mismatch")
    _sha256(profile.target.image_id, "profile.target.image_id", prefixed=True)
    _sha256(profile.target.binary_sha256, "profile.target.binary_sha256", prefixed=False)
    platform_digest = _sha256(
        identity["platform_manifest_digest"],
        "identity.platform_manifest_digest",
        prefixed=True,
    )
    expected_code = f"libphp.so:sha256:{profile.target.binary_sha256}"
    if identity["php_code_build_id"] != expected_code:
        raise ValueError(f"{path.name}: PHP code build identity mismatch")
    expected_bundle = f"{repository}@{platform_digest}"
    if identity["runtime_bundle_id"] != expected_bundle:
        raise ValueError(f"{path.name}: runtime bundle identity mismatch")
    leaf.validate()
    return LoadedManifest(profile, leaf)


__all__ = ("LoadedManifest", "load_manifest")
