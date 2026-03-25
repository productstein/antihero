"""RealtimeGuard — drop-in replacement for Guard using compiled evaluation.

Wraps the CompiledEvaluator with delegation checks, principal validation,
and risk budget tracking that the raw evaluator skips for performance.

Falls back to the interpreted PolicyEngine if the compiled artifact is
stale or unavailable.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from antihero.envelopes.pde import MatchedRule, PolicyDecisionEnvelope, Requirement
from antihero.envelopes.tce import ToolCallEnvelope
from antihero.policy.engine import PolicyEngine
from antihero.policy.matchers import validate_principal
from antihero.policy.schema import PolicyDocument, PrincipalPolicy
from antihero.realtime.compiler import CompiledPolicy, PolicyCompiler
from antihero.realtime.evaluator import CompiledEvaluator
from antihero.realtime.subject import CompiledSubject
from antihero.risk.budget import RiskBudget

logger = logging.getLogger(__name__)


class RealtimeGuard:
    """High-performance policy guard using compiled evaluation.

    Provides the same interface as the interpreted Guard but uses
    the compiled evaluator for the hot path. Includes delegation,
    principal, and risk budget checks that the raw evaluator skips.

    Usage:
        guard = RealtimeGuard(policies)
        pde = guard.evaluate(tce)
    """

    def __init__(
        self,
        policies: list[PolicyDocument],
        *,
        risk_threshold: float = 1.0,
        max_delegation_depth: int = 5,
    ) -> None:
        self._policies = policies
        self._risk_threshold = risk_threshold
        self._max_delegation_depth = max_delegation_depth
        self._risk_budget = RiskBudget(threshold=risk_threshold)

        # Compile policies
        compiler = PolicyCompiler(policies)
        self._artifact = compiler.compile()
        self._evaluator = CompiledEvaluator(self._artifact)

        # Extract principal policies for validation
        self._principal_policies: list[PrincipalPolicy] = []
        for policy in policies:
            self._principal_policies.extend(policy.principals)

        # Fallback interpreter for edge cases
        self._fallback = PolicyEngine(
            policies, risk_threshold=risk_threshold
        )

        self._eval_count = 0
        self._total_eval_ns = 0

        logger.info(
            "RealtimeGuard initialized: %d rules compiled, hash=%s",
            self._artifact.total_rules,
            self._artifact.policy_hash[:12],
        )

    @property
    def artifact(self) -> CompiledPolicy:
        """Access the compiled artifact."""
        return self._artifact

    @property
    def policy_hash(self) -> str:
        """Hash of the compiled policies."""
        return self._artifact.policy_hash

    @property
    def avg_eval_ns(self) -> float:
        """Average evaluation time in nanoseconds."""
        if self._eval_count == 0:
            return 0.0
        return self._total_eval_ns / self._eval_count

    def recompile(self, policies: list[PolicyDocument] | None = None) -> None:
        """Recompile with updated policies."""
        if policies is not None:
            self._policies = policies
        compiler = PolicyCompiler(self._policies)
        self._artifact = compiler.compile()
        self._evaluator = CompiledEvaluator(self._artifact)
        self._fallback = PolicyEngine(
            self._policies, risk_threshold=self._risk_threshold
        )
        logger.info(
            "RealtimeGuard recompiled: %d rules, hash=%s",
            self._artifact.total_rules,
            self._artifact.policy_hash[:12],
        )

    def evaluate(self, tce: ToolCallEnvelope) -> PolicyDecisionEnvelope:
        """Evaluate a TCE using the compiled engine.

        Performs delegation and principal checks before the fast path,
        then uses the compiled evaluator for policy matching.
        """
        try:
            return self._evaluate_inner(tce)
        except Exception as exc:
            logger.warning(
                "Compiled evaluation failed, falling back to interpreter: %s", exc
            )
            return self._fallback.evaluate(tce)

    def _evaluate_inner(self, tce: ToolCallEnvelope) -> PolicyDecisionEnvelope:
        """Inner evaluation with compiled engine."""
        # Phase 0: Delegation depth check
        if tce.subject.delegation_depth > self._max_delegation_depth:
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=(
                    f"Delegation depth {tce.subject.delegation_depth} "
                    f"exceeds max {self._max_delegation_depth}"
                ),
                risk_score=1.0,
            )

        # Phase 0b: Principal validation
        if self._principal_policies:
            allowed, reason = validate_principal(
                principal=tce.subject.principal,
                policies=self._principal_policies,
                action=tce.action,
                agent_id=tce.subject.agent_id,
                delegation_depth=tce.subject.delegation_depth,
            )
            if not allowed:
                return PolicyDecisionEnvelope(
                    tce_id=tce.id,
                    effect="deny",
                    reason=f"Principal validation failed: {reason}",
                    risk_score=1.0,
                )

        # Phase 1: Compiled evaluation (hot path)
        subject = CompiledSubject.from_tce_subject(tce.subject)
        start_ns = time.perf_counter_ns()
        decision = self._evaluator.evaluate(
            action=tce.action,
            resource=tce.resource,
            subject=subject,
            context=tce.context,
        )
        elapsed_ns = time.perf_counter_ns() - start_ns
        self._eval_count += 1
        self._total_eval_ns += elapsed_ns

        # Phase 2: Risk budget check
        if decision.effect != "deny" and self._risk_budget.would_exceed(decision.risk_score):
            new_cumulative = self._risk_budget.peek(decision.risk_score)
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=(
                    f"Risk budget exceeded: {new_cumulative:.2f} > "
                    f"{self._risk_budget.threshold:.2f}"
                ),
                risk_score=decision.risk_score,
                cumulative_risk=new_cumulative,
                matched_rules=tuple(
                    MatchedRule(
                        rule_id=rid,
                        policy_tier=tier,
                        effect=decision.effect,
                        priority=0,
                    )
                    for rid, tier in decision.matched_rule_ids
                ),
            )

        # Phase 3: Commit risk and build PDE
        if decision.effect != "deny":
            self._risk_budget.commit(decision.risk_score)

        matched_rules = tuple(
            MatchedRule(
                rule_id=rid,
                policy_tier=tier,
                effect=decision.effect,
                priority=0,
            )
            for rid, tier in decision.matched_rule_ids
        )

        requirements = tuple(
            Requirement(
                kind=req.get("kind", "custom"),
                params=req.get("params", {}),
            )
            for req in decision.requirements
        )

        return PolicyDecisionEnvelope(
            tce_id=tce.id,
            effect=decision.effect,
            reason=decision.reason,
            denied_by=decision.denied_by,
            risk_score=decision.risk_score,
            cumulative_risk=self._risk_budget.current,
            matched_rules=matched_rules,
            requirements=requirements,
        )
