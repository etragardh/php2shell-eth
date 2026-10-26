"""Low-level recorded HTTP/1.1 transport.

Chains with unusual timing may use ``Http1Connection`` directly. Normal
single-request exchanges use ``SocketHttp1Transport.exchange``.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass

from .http import RequestPlan
from .target import Target


@dataclass(frozen=True)
class Response:
    raw: bytes
    status: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def header(self, name: bytes) -> bytes | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None


@dataclass(frozen=True)
class Exchange:
    response: Response
    request_bytes: int
    response_bytes: int


def parse_close_delimited_response(raw: bytes) -> Response:
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n") if head else []
    status = 0
    if lines:
        try:
            status = int(lines[0].split(b" ", 2)[1])
        except (IndexError, ValueError):
            pass
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        key, marker, value = line.partition(b":")
        if marker:
            headers.append((key.strip(), value.strip()))
    return Response(raw, status, tuple(headers), body if separator else b"")


class Http1Connection:
    def __init__(self, target: Target) -> None:
        self.target = target
        raw = socket.create_connection(
            (target.connect_host, target.port), timeout=target.timeout,
        )
        if target.scheme == "https":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=target.host)
        raw.settimeout(target.timeout)
        self.socket = raw

    def close(self) -> None:
        self.socket.close()

    def __enter__(self) -> "Http1Connection":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def render_head(self, request: RequestPlan) -> bytes:
        request.validate()
        headers = [(b"Host", self.target.host_header.encode("ascii"))]
        headers.extend(request.headers)
        if request.framing == "fixed":
            headers.append((b"Content-Length", str(request.body.length).encode("ascii")))
        else:
            headers.append((b"Transfer-Encoding", b"chunked"))
        headers.append((b"Connection", b"close" if request.connection_close else b"keep-alive"))
        first = f"{request.method} {request.path} HTTP/1.1\r\n".encode("ascii")
        return first + b"".join(key + b": " + value + b"\r\n" for key, value in headers) + b"\r\n"

    def send(self, request: RequestPlan) -> int:
        sent = 0
        head = self.render_head(request)
        self.socket.sendall(head)
        sent += len(head)
        if request.framing == "fixed":
            for chunk in request.body.iter_chunks():
                self.socket.sendall(chunk)
                sent += len(chunk)
        else:
            for chunk in request.body.iter_chunks():
                frame = f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n"
                self.socket.sendall(frame)
                sent += len(frame)
            self.socket.sendall(b"0\r\n\r\n")
            sent += 5
        return sent

    def receive_until_close(self, cap: int) -> bytes:
        data = bytearray()
        while len(data) < cap:
            try:
                block = self.socket.recv(min(65536, cap - len(data)))
            except (ConnectionResetError, socket.timeout):
                break
            if not block:
                break
            data.extend(block)
        return bytes(data)


class SocketHttp1Transport:
    def exchange(
        self,
        target: Target,
        request: RequestPlan,
        *,
        response_cap: int = 8 * 1024 * 1024,
    ) -> Exchange:
        with Http1Connection(target) as connection:
            request_bytes = connection.send(request)
            raw = connection.receive_until_close(response_cap)
        return Exchange(
            response=parse_close_delimited_response(raw),
            request_bytes=request_bytes,
            response_bytes=len(raw),
        )
