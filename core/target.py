"""Network target model used by every chain."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from urllib.parse import urlsplit


def validate_http_path(path: str, *, label: str = "HTTP path") -> str:
    """Validate a raw origin-form request target before it reaches the wire."""
    if not path.startswith("/"):
        raise ValueError(f"{label} must start with /")
    try:
        path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be ASCII") from exc
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in path):
        raise ValueError(f"{label} must not contain spaces or control characters")
    return path


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str
    host_header: str
    connect_host: str
    timeout: float = 30.0

    @classmethod
    def parse(cls, value: str, *, timeout: float = 30.0) -> "Target":
        if not isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("target URL scheme must be http or https")
        if not parsed.hostname:
            raise ValueError("target URL must contain a hostname")
        if parsed.username or parsed.password:
            raise ValueError("target URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("put query parameters in chain options, not TARGET")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError(f"invalid target port: {exc}") from exc
        default_port = 443 if parsed.scheme == "https" else 80
        host_header = parsed.hostname if port == default_port else f"{parsed.hostname}:{port}"
        path = validate_http_path(parsed.path or "/", label="target URL path")
        return cls(
            scheme=parsed.scheme,
            host=parsed.hostname,
            port=port,
            path=path,
            host_header=host_header,
            connect_host=parsed.hostname,
            timeout=timeout,
        )

    @property
    def url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        authority = self.host if self.port == default_port else f"{self.host}:{self.port}"
        return f"{self.scheme}://{authority}{self.path}"


__all__ = ("Target", "validate_http_path")
