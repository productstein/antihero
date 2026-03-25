"""SHA-256 hashing utilities."""

from __future__ import annotations

import hashlib

GENESIS_HASH = "0" * 64


def sha256_hex(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()
