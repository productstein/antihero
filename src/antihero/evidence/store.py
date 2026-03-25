"""JSONL audit store — append-only file storage for AEEs.

Each line is a JSON-serialized AuditEventEnvelope. The file is append-only
and suitable for `tail -f` monitoring.
"""

from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from antihero.envelopes.aee import AuditEventEnvelope


class AbstractAuditStore(ABC):
    """Abstract interface for audit event storage backends."""

    @abstractmethod
    def write(self, aee: AuditEventEnvelope) -> None:
        """Append an AEE to the store."""

    @abstractmethod
    def read_all(self) -> list[AuditEventEnvelope]:
        """Read all AEEs from the store."""

    @abstractmethod
    def read_last(self, n: int = 10) -> list[AuditEventEnvelope]:
        """Read the last N events from the store."""

    @abstractmethod
    def count(self) -> int:
        """Count total events in the store."""


class AuditStore(AbstractAuditStore):
    """Thread-safe, append-only JSONL file store for audit events.

    Args:
        path: Path to the JSONL audit file.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        """Path to the audit file."""
        return self._path

    def write(self, aee: AuditEventEnvelope) -> None:
        """Append an AEE to the store."""
        line = aee.model_dump_json() + "\n"
        with self._lock, self._path.open("a", encoding="utf-8") as f:
            f.write(line)

    def read_all(self) -> list[AuditEventEnvelope]:
        """Read all AEEs from the store."""
        if not self._path.exists():
            return []
        events: list[AuditEventEnvelope] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    events.append(AuditEventEnvelope.model_validate(data))
                except (json.JSONDecodeError, Exception) as exc:
                    raise ValueError(f"Invalid AEE at line {line_num}: {exc}") from exc
        return events

    def read_last(self, n: int = 10) -> list[AuditEventEnvelope]:
        """Read the last N events from the store."""
        all_events = self.read_all()
        return all_events[-n:]

    def count(self) -> int:
        """Count total events in the store."""
        if not self._path.exists():
            return 0
        count = 0
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count
