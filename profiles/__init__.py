"""Dynamic discovery of self-contained executable profile manifests."""

from __future__ import annotations

from importlib import resources

from core.catalog import ProfileCatalog
from core.profile import ProfileSpec
from .modphp_pinned._loader import LoadedManifest, load_manifest


def discover_manifests() -> tuple[LoadedManifest, ...]:
    root = resources.files("profiles.modphp_pinned").joinpath("manifests")
    loaded = tuple(
        load_manifest(item)
        for item in sorted(root.iterdir(), key=lambda value: value.name)
        if item.name.endswith(".json")
    )
    if not loaded:
        raise RuntimeError("no active profile manifests found")
    profile_ids = [item.profile.id for item in loaded]
    if len(profile_ids) != len(set(profile_ids)):
        raise ValueError("duplicate profile id in active manifests")
    track_ids = [item.leaf.track.id for item in loaded]
    if len(track_ids) != len(set(track_ids)):
        raise ValueError("duplicate target track in active manifests")
    return loaded


def discover_profiles() -> dict[str, ProfileSpec[object]]:
    return {item.profile.id: item.profile for item in discover_manifests()}


MANIFESTS = discover_manifests()
PROFILES = {item.profile.id: item.profile for item in MANIFESTS}
PROFILE_LEAVES = {item.leaf.profile_id: item.leaf for item in MANIFESTS}
PROFILE_CATALOG = ProfileCatalog(item.leaf for item in MANIFESTS)

__all__ = (
    "MANIFESTS",
    "PROFILES",
    "PROFILE_LEAVES",
    "PROFILE_CATALOG",
    "discover_manifests",
    "discover_profiles",
)
