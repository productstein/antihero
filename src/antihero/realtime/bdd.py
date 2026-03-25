"""Binary Decision Diagram for deny-dominates policy composition.

Given a set of matched rules, determines the final effect in O(1) for
common cases and O(log N) worst case, without iterating all rules.

The BDD encodes the deny-dominates invariant:
- If ANY matched rule has effect=deny → final effect is deny
- Otherwise merge requirements from allow_with_requirements rules
- Pure allows produce allow

This is simpler than a full BDD — it's a precomputed decision table
indexed by rule combination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class CompiledRule:
    """A rule stripped to its decision-relevant fields."""

    index: int
    rule_id: str
    tier: str
    effect: str  # "allow" | "deny" | "allow_with_requirements"
    priority: int
    risk_score: float
    requirements: tuple[dict[str, Any], ...]


@dataclass(slots=True)
class DecisionResult:
    """The result of BDD evaluation."""

    effect: str
    reason: str
    denied_by: str | None = None
    risk_score: float = 0.0
    requirements: list[dict[str, Any]] = field(default_factory=list)
    matched_rule_ids: list[tuple[str, str]] = field(default_factory=list)  # (rule_id, tier)


class PolicyBDD:
    """Deny-dominates decision table.

    Precomputes which rules are deny rules so the hot path only needs
    to check a bitmap rather than iterating effects.
    """

    def __init__(self, rules: list[CompiledRule]) -> None:
        self._rules = rules
        self._deny_indices: frozenset[int] = frozenset(
            r.index for r in rules if r.effect == "deny"
        )
        self._req_indices: frozenset[int] = frozenset(
            r.index for r in rules if r.effect == "allow_with_requirements"
        )
        self._rule_map: dict[int, CompiledRule] = {r.index: r for r in rules}

    def evaluate(self, matched_indices: set[int]) -> DecisionResult:
        """Evaluate matched rule indices to produce a decision.

        Hot path: O(1) for deny check (set intersection), O(K) for
        requirement collection where K is the number of requirement rules.
        """
        if not matched_indices:
            return DecisionResult(
                effect="deny",
                reason="No matching policy rule found (fail-closed)",
            )

        # Deny dominates: O(1) set intersection
        deny_matches = matched_indices & self._deny_indices
        if deny_matches:
            # Pick highest priority deny
            first_deny_idx = min(
                deny_matches,
                key=lambda i: -self._rule_map[i].priority,
            )
            deny_rule = self._rule_map[first_deny_idx]
            matched_ids = [
                (self._rule_map[i].rule_id, self._rule_map[i].tier)
                for i in matched_indices
                if i in self._rule_map
            ]
            return DecisionResult(
                effect="deny",
                reason=f"Denied by rule '{deny_rule.rule_id}' in {deny_rule.tier} tier",
                denied_by=deny_rule.rule_id,
                matched_rule_ids=matched_ids,
            )

        # Collect requirements and risk scores
        requirements: list[dict[str, Any]] = []
        max_risk: float = 0.0
        matched_ids: list[tuple[str, str]] = []

        for idx in matched_indices:
            rule = self._rule_map.get(idx)
            if rule is None:
                continue
            matched_ids.append((rule.rule_id, rule.tier))
            max_risk = max(max_risk, rule.risk_score)
            if idx in self._req_indices:
                requirements.extend(rule.requirements)

        # Deduplicate requirements by kind
        seen_kinds: dict[str, dict[str, Any]] = {}
        for req in requirements:
            kind = req.get("kind", "custom")
            if kind not in seen_kinds:
                seen_kinds[kind] = req
        deduped = list(seen_kinds.values())

        effect = "allow_with_requirements" if deduped else "allow"
        reason = "Allowed" if effect == "allow" else "Allowed with requirements"

        return DecisionResult(
            effect=effect,
            reason=reason,
            risk_score=max_risk,
            requirements=deduped,
            matched_rule_ids=matched_ids,
        )
