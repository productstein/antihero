"""Threat scanner stub for open source engine.

Full multi-engine threat detection is available in Antihero Cloud.
"""

from __future__ import annotations
from typing import Any


class ThreatScanner:
    """Stub threat scanner. No-op in the open source engine."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def scan(self, *args: Any, **kwargs: Any) -> list:
        return []
