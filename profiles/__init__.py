"""Dynamically discovered profiles used by the exploit runner."""

from importlib import import_module
from pkgutil import iter_modules

from .types import (
    A1Profile,
    A2Profile,
    AbiLayout,
    AllocatorLayout,
    B1Profile,
    B2Profile,
    HeapOffsets,
    Profile,
    SymbolOffsets,
    TargetEnvironment,
)


def _discover_profiles() -> dict[str, Profile]:
    discovered: dict[str, Profile] = {}
    modules = sorted(
        module.name
        for module in iter_modules(__path__)
        if not module.ispkg
        and module.name != "types"
        and not module.name.startswith("_")
    )
    for module_name in modules:
        module = import_module(f"{__name__}.{module_name}")
        profile = getattr(module, "PROFILE", None)
        if not isinstance(profile, Profile):
            raise TypeError(
                f"{module.__name__} must expose PROFILE as a Profile instance"
            )
        profile.validate()
        if profile.name in discovered:
            raise ValueError(f"duplicate profile name: {profile.name}")
        discovered[profile.name] = profile
    if not discovered:
        raise RuntimeError("no profile modules found")
    return discovered


PROFILES = _discover_profiles()
DEFAULT_PROFILE = "php-8.3.35-arm64-official"
if DEFAULT_PROFILE not in PROFILES:
    raise RuntimeError(f"default profile is missing: {DEFAULT_PROFILE}")


__all__ = (
    "A1Profile",
    "A2Profile",
    "AbiLayout",
    "AllocatorLayout",
    "B1Profile",
    "B2Profile",
    "DEFAULT_PROFILE",
    "HeapOffsets",
    "PROFILES",
    "Profile",
    "SymbolOffsets",
    "TargetEnvironment",
)
