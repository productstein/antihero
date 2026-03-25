"""Antihero exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from antihero.envelopes.pde import PolicyDecisionEnvelope


class AntiheroError(Exception):
    """Base exception for all Antihero errors."""


class PolicyError(AntiheroError):
    """Invalid policy file or configuration."""


class PolicyLoadError(PolicyError):
    """Failed to load or parse a policy YAML file."""


class PolicyValidationError(PolicyError):
    """Policy schema validation failed."""


class ActionDeniedError(AntiheroError):
    """A tool call was denied by policy."""

    def __init__(
        self,
        reason: str,
        *,
        pde: PolicyDecisionEnvelope,
        explanation: object | None = None,
    ) -> None:
        super().__init__(reason)
        self.pde = pde
        self.explanation = explanation


class RequirementNotSatisfiedError(AntiheroError):
    """A requirement could not be fulfilled."""


class ChainIntegrityError(AntiheroError):
    """Audit chain verification failed."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__(f"Chain integrity violated: {len(errors)} error(s)")
        self.errors = errors


class RiskBudgetExceededError(AntiheroError):
    """Cumulative risk exceeded threshold."""
