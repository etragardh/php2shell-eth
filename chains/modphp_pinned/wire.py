"""Multipart and raw HTTP helpers used by the modphp-a1b1 stages."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable, Iterator


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


def send_get(host: str, port: int, path: str, timeout: float = 10.0) -> bytes:
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
