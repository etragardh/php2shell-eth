"""Optional per-run evidence recording."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


class EvidenceWriter:
    def __init__(self, root: Path | None) -> None:
        self.root = root
        if self.root is not None:
            self.root.mkdir(parents=True, exist_ok=False)

    @property
    def enabled(self) -> bool:
        return self.root is not None

    def write_bytes(self, name: str, data: bytes) -> str | None:
        if self.root is None:
            return None
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)

    def write_json(self, name: str, value: Any) -> str | None:
        if self.root is None:
            return None
        if is_dataclass(value):
            value = asdict(value)
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
        return str(path)

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
