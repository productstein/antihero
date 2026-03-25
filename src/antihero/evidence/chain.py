"""Hash chain — append-only, tamper-evident audit trail.

Each AEE references the hash of the previous AEE. Modifying any event
invalidates the chain from that point forward.

    h_t = H(Canon(e_t))
    e_t.prev_hash = h_{t-1}
    Genesis: prev_hash = "0" * 64
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from antihero._internal.hashing import GENESIS_HASH, sha256_hex
from antihero.envelopes.aee import AuditEventEnvelope
from antihero.envelopes.pde import PolicyDecisionEnvelope
from antihero.envelopes.tce import ToolCallEnvelope
from antihero.evidence.canonical import jcs_canonicalize

if TYPE_CHECKING:
    from antihero.evidence.store import AbstractAuditStore


class HashChain:
    """Thread-safe hash chain for audit events.

    Usage:
        chain = HashChain()
        aee = chain.append(tce, pde, outcome="executed")
        valid, errors = chain.verify([aee])
    """

    def __init__(
        self, *, sequence: int = 0, current_hash: str = GENESIS_HASH,
    ) -> None:
        self._sequence: int = sequence
        self._current_hash: str = current_hash
        self._lock = threading.Lock()

    @classmethod
    def from_store(cls, store: AbstractAuditStore) -> HashChain:
        """Resume a chain from existing audit events."""
        events = store.read_all()
        if not events:
            return cls()
        last = events[-1]
        return cls(sequence=last.sequence + 1, current_hash=last.this_hash)

    @property
    def current_hash(self) -> str:
        """Hash of the most recent event (or genesis hash if empty)."""
        with self._lock:
            return self._current_hash

    @property
    def sequence(self) -> int:
        """Current sequence number (next event will use this value)."""
        with self._lock:
            return self._sequence

    def append(
        self,
        tce: ToolCallEnvelope,
        pde: PolicyDecisionEnvelope,
        *,
        outcome: str,
        error: str | None = None,
        execution_duration_ms: float | None = None,
        result_hash: str | None = None,
        content_flags: list[dict[str, object]] | None = None,
    ) -> AuditEventEnvelope:
        """Create and append a new audit event to the chain.

        Returns the completed AEE with computed hash.
        """
        with self._lock:
            aee = AuditEventEnvelope(
                sequence=self._sequence,
                tce=tce.model_dump(mode="json"),
                pde=pde.model_dump(mode="json"),
                outcome=outcome,
                error=error,
                execution_duration_ms=execution_duration_ms,
                result_hash=result_hash,
                content_flags=content_flags or [],
                prev_hash=self._current_hash,
                this_hash="",  # Placeholder for hashing
            )

            # Compute hash over canonical form (excluding this_hash)
            hash_input = aee.model_dump(mode="json")
            hash_input["this_hash"] = ""
            canonical_bytes = jcs_canonicalize(hash_input)
            computed_hash = sha256_hex(canonical_bytes)

            # Create final AEE with computed hash
            aee = aee.model_copy(update={"this_hash": computed_hash})

            # Advance chain state
            self._current_hash = computed_hash
            self._sequence += 1

            return aee

    @staticmethod
    def verify(events: list[AuditEventEnvelope]) -> tuple[bool, list[str]]:
        """Verify hash chain integrity.

        Args:
            events: List of AEEs in sequence order.

        Returns:
            (is_valid, list_of_errors)
        """
        errors: list[str] = []
        expected_prev = GENESIS_HASH

        for i, event in enumerate(events):
            # Check sequence
            if event.sequence != i:
                errors.append(f"Event {i}: expected sequence {i}, got {event.sequence}")

            # Check prev_hash linkage
            if event.prev_hash != expected_prev:
                errors.append(
                    f"Event {i}: prev_hash mismatch "
                    f"(expected {expected_prev[:16]}..., got {event.prev_hash[:16]}...)"
                )

            # Recompute hash
            hash_input = event.model_dump(mode="json")
            hash_input["this_hash"] = ""
            canonical_bytes = jcs_canonicalize(hash_input)
            recomputed = sha256_hex(canonical_bytes)

            if event.this_hash != recomputed:
                errors.append(
                    f"Event {i}: this_hash mismatch (tampering detected). "
                    f"Expected {recomputed[:16]}..., got {event.this_hash[:16]}..."
                )

            expected_prev = event.this_hash

        return (len(errors) == 0, errors)
