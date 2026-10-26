"""Calibration types consumed by the pinned A1/B1/A2/B2 chain."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AbiLayout:
    byte_order: str
    pointer_size: int
    reference_size: int
    reference_stride: int
    reference_start: int
    reference_gc_refcount_offset: int
    reference_gc_refcount: int
    reference_gc_type_offset: int
    reference_gc_type: int
    reference_target_offset: int
    reference_zval_type_offset: int
    reference_zval_type: int
    hashtable_gc_refcount_offset: int
    hashtable_gc_refcount: int
    hashtable_gc_type_offset: int
    hashtable_gc_type: int
    hashtable_flags_offset: int
    hashtable_flags: int
    hashtable_mask_offset: int
    hashtable_mask: int
    hashtable_data_offset: int
    hashtable_n_used_offset: int
    hashtable_n_used: int
    hashtable_n_elements_offset: int
    hashtable_n_elements: int
    hashtable_size_offset: int
    hashtable_size: int
    hashtable_internal_pointer_offset: int
    hashtable_internal_pointer: int
    hashtable_next_free_offset: int
    hashtable_next_free: int
    hashtable_destructor_offset: int
    execute_data_offset: int
    execute_call_info_offset: int
    execute_call_info: int
    execute_num_args_offset: int
    execute_num_args: int
    execute_argument_offset: int
    execute_argument_type_offset: int
    execute_argument_type: int
    execute_argument_extra_offset: int
    execute_argument_extra: int
    command_string_offset: int
    string_gc_refcount_offset: int
    string_gc_refcount: int
    string_gc_type_offset: int
    string_gc_type: int
    string_hash_offset: int
    string_hash: int
    string_length_offset: int
    string_data_offset: int


@dataclass(frozen=True)
class AllocatorLayout:
    chunk_alignment: int
    page_size: int
    user_pointer_min: int
    user_pointer_max: int
    pointer_alignment: int
    chunk_heap_offset: int
    chunk_next_offset: int
    chunk_prev_offset: int
    chunk_free_pages_offset: int
    chunk_free_tail_offset: int
    chunk_number_offset: int
    chunk_header_size: int
    heap_slot_from_main: int
    max_free_pages: int
    min_free_tail: int
    max_free_tail: int
    max_chunk_number: int
    image_alignment: int
    image_window: int
    min_libphp_main_delta: int
    max_libphp_main_delta: int
    min_dtor_repetitions: int
    main_cluster_min_slots: int = 0
    main_cluster_min_unique: int = 0
    main_cluster_min_unique_ratio: float = 0.0


@dataclass(frozen=True)
class SymbolOffsets:
    zval_ptr_dtor: int
    zif_system: int


@dataclass(frozen=True)
class HeapOffsets:
    stale_session_id: int
    stale_session_reference: int
    fake_array: int


@dataclass(frozen=True)
class A1Profile:
    sid_size: int
    sid_late: bool
    files: int
    depth: int
    live_files: int
    content_type_1: int
    content_type_2: int
    fillers: int
    filler_name: int
    filler_value: int
    big: int
    big_size: int
    big_name: int
    big_name_count: int
    big_alt_name: int
    tail_big_size: int
    tail_big_count: int
    burners: int
    burner_size: int
    burner_name: int
    burner_long_name_count: int
    burner_long_name: int
    late_groom_fields: int
    late_groom_name: int
    late_groom_value: int
    late_groom_alt_value_count: int
    late_groom_alt_value: int
    released_fields: int
    released_name: int
    released_value: int
    released_alt_value_count: int
    released_alt_value: int
    released_replacement_value: int
    released_long_replacement_count: int
    released_long_replacement_value: int
    progress_size: int
    query_params: int
    query_name_length: int
    query_value_length: int
    query_long_name_count: int
    query_long_name_length: int
    query_released_fields: int
    query_released_name_length: int
    query_released_value_length: int
    query_released_replacement_length: int
    query_released_long_replacement_count: int
    query_released_long_replacement_length: int
    query_secondary_released_fields: int
    query_secondary_released_name_length: int
    query_secondary_released_value_length: int
    query_secondary_released_replacement_length: int
    transport_chunk_size: int
    expected_status: int
    expected_cookie: bool
    calibration_file_candidates: tuple[int, ...]


@dataclass(frozen=True)
class B1ReleasePlan:
    spray_indices: tuple[int, ...]
    post_release_pages: tuple[int, ...] = ()


@dataclass(frozen=True)
class B1Profile:
    fake_length: int
    data_start: int
    sprays: int
    page_spec: tuple[int | None, ...]
    tail_pages: int | None
    release_sprays: bool | B1ReleasePlan
    carrier_sprays: int
    carrier_pages: int
    nested_fields: int
    nested_depth: int
    small_fields: int
    small_name_size: int
    small_value_size: int
    small_after_nested: bool
    fake_string_gc_refcount: int
    fake_string_gc_type: int
    fake_string_hash: int
    marker: bytes
    transport_chunk_size: int
    expected_status: int


@dataclass(frozen=True)
class A2Profile:
    parts: int
    depth: int
    fillers: int
    expected_status: int


@dataclass(frozen=True)
class B2Profile:
    first_sprays: int
    second_sprays: int
    value_length: int
    reference_refcount: int
    name_length: int
    hold_seconds: float


__all__ = (
    "A1Profile",
    "A2Profile",
    "AbiLayout",
    "AllocatorLayout",
    "B1Profile",
    "B1ReleasePlan",
    "B2Profile",
    "HeapOffsets",
    "SymbolOffsets",
)
