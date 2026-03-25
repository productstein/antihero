"""Notification manager stub for open source engine.

Full notification support is available in Antihero Cloud.
"""

from __future__ import annotations
from typing import Any


class NotificationManager:
    """Stub notification manager. No-op in the open source engine."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def notify(self, *args: Any, **kwargs: Any) -> None:
        pass
