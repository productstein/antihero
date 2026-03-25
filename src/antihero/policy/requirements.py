"""Requirement handlers.

Requirements are safety "circuit breakers" — conditions that must be
satisfied before a gated action can proceed. Each handler knows how to
check and satisfy a specific kind of requirement.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from antihero._internal.hashing import sha256_hex
from antihero.envelopes.pde import HumanProofPayload, Requirement
from antihero.envelopes.tce import ToolCallEnvelope
from antihero.exceptions import RequirementNotSatisfiedError

if TYPE_CHECKING:
    from antihero.policy.rate_limiter import RateLimiter


def _compute_action_hash(tce: ToolCallEnvelope) -> str:
    """Compute SHA-256 hash of action + resource + parameters for approval binding."""
    import json
    canonical = json.dumps(
        {"action": tce.action, "resource": tce.resource, "parameters": tce.parameters},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_hex(canonical.encode())


def handle_requirement(
    requirement: Requirement,
    tce: ToolCallEnvelope,
    *,
    confirm_callback: Callable[[str], bool] | None = None,
    mfa_callback: Callable[[ToolCallEnvelope], bool] | None = None,
    human_proof_callback: Callable[[ToolCallEnvelope, dict[str, Any]], HumanProofPayload | None] | None = None,
    rate_limiter: RateLimiter | None = None,
) -> Requirement:
    """Attempt to satisfy a requirement. Returns updated requirement.

    Args:
        requirement: The requirement to satisfy.
        tce: The TCE being evaluated.
        confirm_callback: Optional callback for user confirmation.
                         Signature: (message: str) -> bool
        mfa_callback: Optional callback for MFA verification.
                     Signature: (tce: ToolCallEnvelope) -> bool
        human_proof_callback: Optional callback for human proof-of-approval.
                     Signature: (tce, params) -> HumanProofPayload | None
                     Receives the TCE and requirement params (method, timeout, etc.).
                     Returns a HumanProofPayload on success, None on failure.
        rate_limiter: Optional rate limiter for enforcing rate limits.

    Returns:
        Updated Requirement with satisfied=True if fulfilled.

    Raises:
        RequirementNotSatisfiedError: If the requirement cannot be satisfied.
    """
    match requirement.kind:
        case "log":
            # Log requirements are always satisfied (they just record)
            return requirement.model_copy(update={"satisfied": True})

        case "confirm":
            if confirm_callback is None:
                raise RequirementNotSatisfiedError(
                    "Confirmation required but no confirmation handler available"
                )
            message = requirement.params.get(
                "message", f"Allow {tce.action} on {tce.resource}?"
            )
            if confirm_callback(message):
                return requirement.model_copy(update={"satisfied": True})
            raise RequirementNotSatisfiedError("User denied confirmation")

        case "redact":
            # Mark satisfied — actual redaction is applied by Guard
            # using ContentInspector.apply_redactions() before execution
            return requirement.model_copy(update={"satisfied": True})

        case "sandbox":
            # Mark satisfied — Guard.execute() wraps fn() in a timeout
            timeout_sec = requirement.params.get("timeout_seconds", 30)
            return requirement.model_copy(update={
                "satisfied": True,
                "params": {**requirement.params, "timeout_seconds": timeout_sec},
            })

        case "rate_limit":
            if rate_limiter is None:
                # No limiter configured — fail open with warning
                return requirement.model_copy(update={"satisfied": True})
            key = f"{tce.subject.agent_id}:{tce.action}"
            max_count = requirement.params.get("max_count", 100)
            window = requirement.params.get("window_seconds", 3600)
            if not rate_limiter.check(key, max_count, window):
                raise RequirementNotSatisfiedError(
                    f"Rate limit exceeded: {max_count} actions per {window}s "
                    f"for {tce.action}"
                )
            rate_limiter.record(key)
            return requirement.model_copy(update={"satisfied": True})

        case "mfa":
            if mfa_callback is None:
                raise RequirementNotSatisfiedError(
                    "MFA required but no MFA handler available"
                )
            if mfa_callback(tce):
                return requirement.model_copy(update={"satisfied": True})
            raise RequirementNotSatisfiedError("MFA verification failed")

        case "simulate":
            # Simulation requirement — validate action in digital twin
            from antihero.simulation.digital_twin.config import SimulationConfig
            from antihero.simulation.digital_twin.validator import SimulationValidator

            sim_config = SimulationConfig.from_requirement_params(requirement.params)
            validator = SimulationValidator()
            result = validator.validate(sim_config, tce.parameters)

            if result.safe:
                return requirement.model_copy(update={
                    "satisfied": True,
                    "params": {**requirement.params, "sim_result": result.to_dict()},
                })
            violation_summary = "; ".join(v.description for v in result.violations[:3])
            raise RequirementNotSatisfiedError(
                f"Simulation validation failed: {violation_summary}"
            )

        case "human_proof":
            if human_proof_callback is None:
                raise RequirementNotSatisfiedError(
                    "Human proof required but no human_proof_callback available"
                )
            # Build context for the callback: method, timeout, action hash
            action_hash = _compute_action_hash(tce)
            callback_params = {
                **requirement.params,
                "action_hash": action_hash,
            }
            proof = human_proof_callback(tce, callback_params)
            if proof is None:
                raise RequirementNotSatisfiedError(
                    "Human proof verification failed or was denied"
                )
            # Verify the proof covers the correct action hash
            if proof.action_hash != action_hash:
                raise RequirementNotSatisfiedError(
                    "Human proof action_hash mismatch — approval does not cover this action"
                )
            return requirement.model_copy(update={
                "satisfied": True,
                "proof": proof,
            })

        case _:
            raise RequirementNotSatisfiedError(
                f"Unknown requirement kind: {requirement.kind}"
            )
