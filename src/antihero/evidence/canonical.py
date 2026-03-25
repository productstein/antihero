"""RFC 8785 JSON Canonicalization Scheme wrapper.

Provides deterministic JSON serialization for hashing and signing.
Uses the rfc8785 package (by Trail of Bits) for standards-compliant output.
"""

from __future__ import annotations

from typing import Any

import rfc8785


def jcs_canonicalize(obj: dict[str, Any]) -> bytes:
    """Canonicalize a dict to UTF-8 bytes using RFC 8785 JCS.

    This ensures identical objects always produce identical byte sequences,
    regardless of key ordering or formatting.
    """
    return rfc8785.dumps(obj)
