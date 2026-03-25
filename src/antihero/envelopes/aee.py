"""Audit Event Envelope — tamper-evident receipt.

AEEs form a hash chain. Each event references the hash of the previous event,
making tampering detectable. This is the evidence layer's core primitive.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from antihero._internal.time import utcnow


class AuditEventEnvelope(BaseModel):
    """Hash-chained audit record. One per gated action.

    Serialized to JSONL. The hash chain provides tamper-evidence:
    modifying any event invalidates all subsequent hashes.
    """

    model_config = ConfigDict(frozen=True)

    envelope_type: Literal["aee"] = "aee"
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utcnow)
    sequence: int = Field(..., ge=0, description="Monotonic sequence number in this chain")
    tce: dict[str, Any] = Field(..., description="Serialized TCE snapshot")
    pde: dict[str, Any] = Field(..., description="Serialized PDE snapshot")
    outcome: Literal[
        "executed",
        "blocked",
        "requirements_pending",
        "requirements_satisfied",
        "error",
    ]
    error: str | None = Field(default=None, description="Error message if outcome is 'error'")
    execution_duration_ms: float | None = Field(
        default=None,
        description="Wall-clock execution time in milliseconds",
    )
    result_hash: str | None = Field(
        default=None,
        description="SHA-256 of the tool's return value (for non-sensitive results)",
    )
    prev_hash: str = Field(
        ...,
        description="SHA-256 of the previous AEE. Genesis: 64 zero chars",
    )
    this_hash: str = Field(
        default="",
        description="SHA-256 of this AEE's canonical form (excluding this_hash itself)",
    )
    content_flags: list[dict[str, Any]] = Field(
        default_factory=list,
        description="DLP/PII findings from content inspection",
    )
    signature: str | None = Field(
        default=None,
        description="Optional Ed25519 signature over this_hash",
    )
    signer_public_key: str | None = Field(
        default=None,
        description="Hex-encoded Ed25519 public key of the signer",
    )
