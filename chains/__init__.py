"""Explicit registry of stable exploit-chain contracts."""

from __future__ import annotations

from core.chain import Chain
from .modphp_pinned import CHAIN as MODPHP_PINNED


def discover_chains() -> dict[str, Chain]:
    """Return the reviewed chain allowlist; research packages stay inactive."""
    chains: tuple[Chain, ...] = (MODPHP_PINNED,)
    result = {chain.id: chain for chain in chains}
    if len(result) != len(chains):
        raise ValueError("duplicate stable chain id")
    return result


CHAINS = discover_chains()

__all__ = ("CHAINS", "discover_chains")
