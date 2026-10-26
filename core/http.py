"""Repeatable HTTP body and request plans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator


ChunkFactory = Callable[[], Iterable[bytes]]


@dataclass(frozen=True)
class BodyPlan:
    factory: ChunkFactory
    length: int | None

    @classmethod
    def from_bytes(cls, data: bytes) -> "BodyPlan":
        return cls(lambda: (data,), len(data))

    def iter_chunks(self) -> Iterator[bytes]:
        for chunk in self.factory():
            if not isinstance(chunk, bytes):
                raise TypeError("body chunks must be bytes")
            if chunk:
                yield chunk


@dataclass(frozen=True)
class RequestPlan:
    method: str
    path: str
    headers: tuple[tuple[bytes, bytes], ...]
    body: BodyPlan
    framing: str
    connection_close: bool = True

    def validate(self) -> None:
        if self.framing not in ("fixed", "chunked"):
            raise ValueError("request framing must be fixed or chunked")
        if self.framing == "fixed" and self.body.length is None:
            raise ValueError("fixed framing requires a known body length")
        if not self.method or not self.path.startswith("/"):
            raise ValueError("invalid request line")
