"""Timestamp utilities."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(UTC)
