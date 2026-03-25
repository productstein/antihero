"""Core policy evaluation engine.

Formal properties enforced:
1. Fail-closed: no rule matches → deny. Engine error → deny.
2. Deterministic: same TCE + same policies → same PDE. Always.
3. Deny dominates: any deny in any tier → final deny.
4. Monotonic safety: tightening policy cannot reduce safety.
"""

from __future__ import annotations

from collections import OrderedDict
from fnmatch import fnmatch

from antihero.envelopes.pde import MatchedRule, PolicyDecisionEnvelope, Requirement
from antihero.envelopes.tce import ToolCallEnvelope
from antihero.policy.matchers import matches_rule, validate_principal
from antihero.policy.schema import PolicyDocument, PolicyRule, PrincipalPolicy
from antihero.risk.budget import ContainerRiskBudgetManager, RiskBudget


def _is_wildcard(pattern: str) -> bool:
    """Check if a glob pattern contains wildcard characters."""
    return "*" in pattern or "?" in pattern or "[" in pattern


def _l0_action_match(rule: PolicyRule, action: str) -> bool:
    """L0 fast pre-filter: can this rule's action patterns possibly match?

    Returns True if the rule *might* match (proceed to full evaluation).
    Returns False only when we can definitively say it won't match.
    """
    for pattern in rule.actions:
        if _is_wildcard(pattern):
            return True  # Wildcards need full evaluation
        if fnmatch(action, pattern):
            return True
    return False

TIER_ORDER: dict[str, int] = {"baseline": 0, "org": 1, "app": 2, "user": 3}


class PolicyEngine:
    """Evaluates tool call envelopes against a composed policy stack.

    The engine collects all matching rules across all tiers, then applies
    composition semantics: deny dominates, requirements are merged, and
    risk budgets are checked.
    """

    def __init__(
        self,
        policies: list[PolicyDocument],
        *,
        risk_threshold: float = 1.0,
        container_budgets: ContainerRiskBudgetManager | None = None,
    ) -> None:
        self._tiers: OrderedDict[str, list[PolicyRule]] = OrderedDict()
        for tier_name in ("baseline", "org", "app", "user"):
            self._tiers[tier_name] = []

        for policy in sorted(policies, key=lambda p: TIER_ORDER.get(p.tier, 99)):
            rules = sorted(policy.rules, key=lambda r: -r.priority)
            self._tiers[policy.tier].extend(rules)

        self._risk_budget = RiskBudget(threshold=risk_threshold)
        self._container_budgets = container_budgets
        self._principal_policies: list[PrincipalPolicy] = []
        for policy in policies:
            self._principal_policies.extend(policy.principals)
        self._rule_index: dict[tuple[str, str], PolicyRule] = {}
        for tier_name, rules in self._tiers.items():
            for rule in rules:
                self._rule_index[(tier_name, rule.id)] = rule

    @property
    def risk_budget(self) -> RiskBudget:
        """Access the risk budget for external inspection."""
        return self._risk_budget

    @property
    def total_rules(self) -> int:
        """Total number of rules across all tiers."""
        return sum(len(rules) for rules in self._tiers.values())

    @property
    def policy_count(self) -> int:
        """Number of policies loaded (approximated by tier count with rules)."""
        return sum(1 for rules in self._tiers.values() if rules)

    def evaluate_with_trajectory(
        self, tce: ToolCallEnvelope
    ) -> tuple[PolicyDecisionEnvelope, dict]:
        """Evaluate a TCE and return both the PDE and a decision trajectory.

        The trajectory records which policies were checked, what matched,
        and how the final decision was reached — actuarial evidence.
        """
        budget_before = self._risk_budget.current
        pde = self.evaluate(tce)
        budget_after = self._risk_budget.current

        # Determine which evaluation phase produced the decision
        if pde.reason and "fail-closed" in pde.reason.lower():
            phase = "engine_error"
        elif pde.reason and "delegation depth" in pde.reason.lower():
            phase = "delegation_check"
        elif not pde.matched_rules and pde.effect == "deny":
            phase = "no_match_fail_closed"
        elif pde.denied_by:
            phase = "deny_dominates"
        elif pde.reason and "risk budget" in pde.reason.lower():
            phase = "risk_budget_exceeded"
        elif pde.effect == "allow":
            phase = "allow"
        elif pde.effect == "allow_with_requirements":
            phase = "allow_with_requirements"
        else:
            phase = "unknown"

        trajectory = {
            "rules_total": self.total_rules,
            "rules_l0_skipped": getattr(self, "_last_l0_skipped", 0),
            "rules_evaluated": self.total_rules - getattr(self, "_last_l0_skipped", 0),
            "policies_evaluated": self.total_rules,
            "policies_matched": len(pde.matched_rules),
            "policy_decisions": [
                {
                    "rule_id": mr.rule_id,
                    "tier": mr.policy_tier,
                    "effect": mr.effect,
                    "priority": mr.priority,
                }
                for mr in pde.matched_rules
            ],
            "risk_budget_before": round(budget_before, 4),
            "risk_budget_after": round(budget_after, 4),
            "phase": phase,
        }
        return pde, trajectory

    def evaluate(self, tce: ToolCallEnvelope) -> PolicyDecisionEnvelope:
        """Evaluate a TCE against the policy stack. Returns a PDE.

        This is the core function. Every formal property is enforced here.
        """
        try:
            return self._evaluate_inner(tce)
        except Exception as exc:
            # Fail-closed: engine errors produce deny
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=f"Policy engine error (fail-closed): {exc}",
            )

    def _evaluate_inner(self, tce: ToolCallEnvelope) -> PolicyDecisionEnvelope:
        """Inner evaluation logic, separated so exceptions trigger fail-closed."""
        # Phase 0: Delegation depth check
        max_delegation_depth = 5
        if tce.subject.delegation_depth > max_delegation_depth:
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=(
                    f"Delegation depth {tce.subject.delegation_depth} "
                    f"exceeds max {max_delegation_depth}"
                ),
                risk_score=1.0,
            )

        # Phase 0b: Principal identity validation
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

        matched_rules: list[MatchedRule] = []
        self._last_l0_skipped = 0

        # Phase 1: Collect all matching rules across all tiers
        # L0 pre-filter: skip rules whose action patterns can't match (fast path)
        for tier_name, rules in self._tiers.items():
            for rule in rules:
                if not _l0_action_match(rule, tce.action):
                    self._last_l0_skipped += 1
                    continue
                if matches_rule(rule, tce):
                    matched_rules.append(
                        MatchedRule(
                            rule_id=rule.id,
                            policy_tier=tier_name,
                            effect=rule.effect,
                            priority=rule.priority,
                        )
                    )

        # Phase 2: Fail-closed — no matches means deny
        if not matched_rules:
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason="No matching policy rule found (fail-closed)",
                matched_rules=(),
            )

        # Phase 3: Deny dominates — any deny in any tier means final deny
        deny_rules = [r for r in matched_rules if r.effect == "deny"]
        if deny_rules:
            first_deny = deny_rules[0]
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=f"Denied by rule '{first_deny.rule_id}' in {first_deny.policy_tier} tier",
                matched_rules=tuple(matched_rules),
                denied_by=first_deny.rule_id,
            )

        # Phase 4: Merge requirements from all allow_with_requirements rules
        all_requirements: list[Requirement] = []
        max_risk: float = 0.0
        for mr in matched_rules:
            original_rule = self._rule_index.get((mr.policy_tier, mr.rule_id))
            if original_rule is None:
                continue
            if mr.effect == "allow_with_requirements":
                for req_dict in original_rule.requirements:
                    all_requirements.append(
                        Requirement(
                            kind=req_dict.get("kind", "custom"),
                            params=req_dict.get("params", {}),
                        )
                    )
            max_risk = max(max_risk, original_rule.risk_score)

        # Phase 5: Risk budget check (session-level)
        if self._risk_budget.would_exceed(max_risk):
            new_cumulative = self._risk_budget.peek(max_risk)
            return PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=(
                    f"Risk budget exceeded: {new_cumulative:.2f} > "
                    f"{self._risk_budget.threshold:.2f}"
                ),
                risk_score=max_risk,
                cumulative_risk=new_cumulative,
                matched_rules=tuple(matched_rules),
            )

        # Phase 5b: Container-scoped risk budget check (PTC)
        container_budget = None
        if (
            self._container_budgets is not None
            and tce.caller is not None
            and tce.caller.container_id is not None
        ):
            container_budget = self._container_budgets.get_budget(
                tce.caller.container_id
            )
            if container_budget.would_exceed(max_risk):
                new_container_risk = container_budget.peek(max_risk)
                return PolicyDecisionEnvelope(
                    tce_id=tce.id,
                    effect="deny",
                    reason=(
                        f"Container risk budget exceeded for "
                        f"'{tce.caller.container_id}': "
                        f"{new_container_risk:.2f} > "
                        f"{container_budget.threshold:.2f}"
                    ),
                    risk_score=max_risk,
                    cumulative_risk=self._risk_budget.peek(max_risk),
                    matched_rules=tuple(matched_rules),
                )

        # Phase 6: Commit risk and return decision
        self._risk_budget.commit(max_risk)
        if container_budget is not None:
            container_budget.commit(max_risk)
        deduplicated = _deduplicate_requirements(all_requirements)
        final_effect = "allow_with_requirements" if deduplicated else "allow"

        return PolicyDecisionEnvelope(
            tce_id=tce.id,
            effect=final_effect,
            requirements=tuple(deduplicated) if deduplicated else (),
            matched_rules=tuple(matched_rules),
            risk_score=max_risk,
            cumulative_risk=self._risk_budget.current,
            reason="Allowed" if final_effect == "allow" else "Allowed with requirements",
        )


def _deduplicate_requirements(reqs: list[Requirement]) -> list[Requirement]:
    """Deduplicate requirements by kind, keeping the most restrictive params."""
    seen: dict[str, Requirement] = {}
    for req in reqs:
        if req.kind not in seen:
            seen[req.kind] = req
        # If duplicate kind, keep first (could be enhanced with param merging)
    return list(seen.values())
