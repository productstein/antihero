"""Compiled policy evaluator — the hot-path decision engine.

Evaluates actions against a CompiledPolicy artifact in sub-100μs.
This replaces the interpreted PolicyEngine for robotics control loops.

The evaluator does NOT handle:
- Delegation depth checks (done in Guard wrapper)
- Principal validation (done in Guard wrapper)
- Risk budget tracking (done in Guard wrapper)
- Threat scanning (off hot path)
- Content inspection (off hot path)

It handles ONLY: action → policy decision (the inner evaluation loop).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any

from antihero.realtime.bytecode import execute_conditions
from antihero.realtime.compiler import CompiledPolicy
from antihero.realtime.subject import CompiledSubject


@dataclass(slots=True, frozen=True)
class PolicyDecision:
    """Lightweight decision output — no Pydantic overhead on hot path."""

    effect: str  # "allow" | "deny" | "allow_with_requirements"
    reason: str
    denied_by: str | None = None
    risk_score: float = 0.0
    requirements: tuple[dict[str, Any], ...] = ()
    matched_rule_ids: tuple[tuple[str, str], ...] = ()  # (rule_id, tier)


class CompiledEvaluator:
    """Evaluates actions against a compiled policy artifact.

    This is the hot-path class. All methods are designed for minimal
    allocation and maximum throughput.
    """

    def __init__(self, artifact: CompiledPolicy) -> None:
        self._artifact = artifact

    @property
    def artifact(self) -> CompiledPolicy:
        """Access the underlying artifact."""
        return self._artifact

    @property
    def policy_hash(self) -> str:
        """Hash of the compiled policies."""
        return self._artifact.policy_hash

    def evaluate(
        self,
        action: str,
        resource: str,
        subject: CompiledSubject,
        context: Any = None,
    ) -> PolicyDecision:
        """Evaluate an action against compiled policies.

        This is the hot-path function. Target: <100μs.

        Args:
            action: Canonical action name (e.g., 'motion.arm.move')
            resource: Target resource (e.g., 'shelf/top-row')
            subject: Pre-compiled subject identity
            context: Optional context object for condition evaluation

        Returns:
            PolicyDecision with effect, reason, and matched rules.
        """
        art = self._artifact

        # Step 1: Action trie lookup — O(|action segments|)
        action_candidates = art.action_trie.match(action)

        if not action_candidates:
            return PolicyDecision(
                effect="deny",
                reason="No matching policy rule found (fail-closed)",
            )

        # Step 2: Resource trie lookup — O(|resource segments|)
        resource_candidates = art.resource_trie.match(resource)

        # Step 3: Intersect action and resource candidates
        candidates = action_candidates & resource_candidates

        if not candidates:
            return PolicyDecision(
                effect="deny",
                reason="No matching policy rule found (fail-closed)",
            )

        # Step 4: Filter by subject match
        subject_matched: set[int] = set()
        for idx in candidates:
            rule = art.rules[idx]
            if subject.matches_patterns(rule.subjects):
                subject_matched.add(idx)

        if not subject_matched:
            return PolicyDecision(
                effect="deny",
                reason="No matching policy rule found (fail-closed)",
            )

        # Step 5: Evaluate conditions (bytecode VM)
        # Build a minimal context object for condition evaluation
        condition_ctx = _ConditionContext(action, resource, subject, context)
        final_matched: set[int] = set()

        for idx in subject_matched:
            rule = art.rules[idx]
            if execute_conditions(rule.conditions, condition_ctx):
                final_matched.add(idx)

        if not final_matched:
            return PolicyDecision(
                effect="deny",
                reason="No matching policy rule found (fail-closed)",
            )

        # Step 6: BDD evaluation — deny-dominates composition
        result = art.bdd.evaluate(final_matched)

        return PolicyDecision(
            effect=result.effect,
            reason=result.reason,
            denied_by=result.denied_by,
            risk_score=result.risk_score,
            requirements=tuple(result.requirements),
            matched_rule_ids=tuple(result.matched_rule_ids),
        )


class _ConditionContext:
    """Minimal context object for condition bytecode evaluation.

    Provides attribute access matching TCE field paths without
    creating a full Pydantic model on the hot path.
    """

    __slots__ = ("action", "resource", "subject", "context", "parameters")

    def __init__(
        self,
        action: str,
        resource: str,
        subject: CompiledSubject,
        context: Any,
    ) -> None:
        self.action = action
        self.resource = resource
        self.subject = subject
        self.context = context if context is not None else {}
        self.parameters = {}
