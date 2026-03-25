"""Policy Decision Envelope — the output of the policy engine.

A PDE tells the enforcement layer what to do: allow, deny, or allow with
requirements that must be satisfied before execution proceeds.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from antihero._internal.time import utcnow


class HumanProofPayload(BaseModel):
    """Cryptographic proof that a verified human approved a specific action."""

    model_config = ConfigDict(frozen=True)

    method: str = Field(..., description="Verification method: passkey | totp | webhook | slack")
    approver_id: str = Field(..., description="Verified identity of the approver")
    approved_at: datetime = Field(default_factory=utcnow)
    action_hash: str = Field(..., description="SHA-256 of action + resource + parameters")
    signature: str = Field(default="", description="Ed25519 or WebAuthn signature over action_hash")
    device_attestation: str | None = Field(default=None, description="WebAuthn device attestation")
    metadata: dict[str, Any] = Field(default_factory=dict)


class Requirement(BaseModel):
    """A condition that must be fulfilled before execution proceeds."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["confirm", "mfa", "redact", "sandbox", "rate_limit", "log", "human_proof", "simulate", "custom"]
    params: dict[str, Any] = Field(default_factory=dict)
    satisfied: bool = False
    proof: HumanProofPayload | None = Field(default=None, description="Cryptographic proof payload for human_proof requirements")


class MatchedRule(BaseModel):
    """Records which policy rule contributed to this decision."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    policy_tier: Literal["baseline", "org", "app", "user"]
    effect: Literal["allow", "deny", "allow_with_requirements"]
    priority: int = 0


class PolicyDecisionEnvelope(BaseModel):
    """The gate decision for a TCE. Produced by the policy engine.

    Invariants enforced by validators:
    - Deny decisions must include a reason.
    - Requirements are only valid with 'allow_with_requirements' effect.
    """

    model_config = ConfigDict(frozen=True)

    envelope_type: Literal["pde"] = "pde"
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utcnow)
    tce_id: UUID = Field(..., description="The TCE this decision applies to")
    effect: Literal["allow", "deny", "allow_with_requirements"]
    requirements: tuple[Requirement, ...] = Field(default_factory=tuple)
    matched_rules: tuple[MatchedRule, ...] = Field(default_factory=tuple)
    reason: str = Field(default="", description="Human-readable explanation")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cumulative_risk: float = Field(default=0.0, ge=0.0)
    denied_by: str | None = Field(
        default=None,
        description="If denied, which rule ID caused it",
    )

    @model_validator(mode="after")
    def _deny_requires_reason(self) -> PolicyDecisionEnvelope:
        if self.effect == "deny" and not self.reason:
            raise ValueError("Deny decisions must include a reason")
        return self

    @model_validator(mode="after")
    def _requirements_only_on_gated(self) -> PolicyDecisionEnvelope:
        if self.effect != "allow_with_requirements" and self.requirements:
            raise ValueError("Requirements only valid with 'allow_with_requirements' effect")
        return self
