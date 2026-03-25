"""Tests for the deny-dominates BDD."""

import pytest

from antihero.realtime.bdd import CompiledRule, DecisionResult, PolicyBDD


def _rule(
    index: int,
    rule_id: str,
    tier: str = "app",
    effect: str = "allow",
    priority: int = 0,
    risk_score: float = 0.0,
    requirements: tuple = (),
) -> CompiledRule:
    return CompiledRule(
        index=index,
        rule_id=rule_id,
        tier=tier,
        effect=effect,
        priority=priority,
        risk_score=risk_score,
        requirements=requirements,
    )


class TestPolicyBDD:
    """Test deny-dominates decision logic."""

    def test_no_matches_fail_closed(self) -> None:
        bdd = PolicyBDD([_rule(0, "r1")])
        result = bdd.evaluate(set())
        assert result.effect == "deny"
        assert "fail-closed" in result.reason

    def test_single_allow(self) -> None:
        bdd = PolicyBDD([_rule(0, "r1", effect="allow")])
        result = bdd.evaluate({0})
        assert result.effect == "allow"

    def test_single_deny(self) -> None:
        bdd = PolicyBDD([_rule(0, "r1", effect="deny")])
        result = bdd.evaluate({0})
        assert result.effect == "deny"
        assert result.denied_by == "r1"

    def test_deny_dominates_allow(self) -> None:
        """Any deny in matched rules → final deny, regardless of allows."""
        bdd = PolicyBDD([
            _rule(0, "allow-rule", effect="allow"),
            _rule(1, "deny-rule", effect="deny"),
        ])
        result = bdd.evaluate({0, 1})
        assert result.effect == "deny"
        assert result.denied_by == "deny-rule"

    def test_deny_dominates_with_requirements(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "gated", effect="allow_with_requirements",
                  requirements=({"kind": "mfa"},)),
            _rule(1, "blocker", effect="deny"),
        ])
        result = bdd.evaluate({0, 1})
        assert result.effect == "deny"
        assert result.denied_by == "blocker"

    def test_highest_priority_deny_selected(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "low-deny", effect="deny", priority=1),
            _rule(1, "high-deny", effect="deny", priority=10),
        ])
        result = bdd.evaluate({0, 1})
        assert result.denied_by == "high-deny"

    def test_allow_with_requirements(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "gated", effect="allow_with_requirements",
                  requirements=({"kind": "mfa", "params": {}},)),
        ])
        result = bdd.evaluate({0})
        assert result.effect == "allow_with_requirements"
        assert len(result.requirements) == 1
        assert result.requirements[0]["kind"] == "mfa"

    def test_requirements_deduplicated(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "r1", effect="allow_with_requirements",
                  requirements=({"kind": "mfa"},)),
            _rule(1, "r2", effect="allow_with_requirements",
                  requirements=({"kind": "mfa"},)),
        ])
        result = bdd.evaluate({0, 1})
        assert result.effect == "allow_with_requirements"
        assert len(result.requirements) == 1

    def test_risk_score_max(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "r1", effect="allow", risk_score=0.3),
            _rule(1, "r2", effect="allow", risk_score=0.7),
        ])
        result = bdd.evaluate({0, 1})
        assert result.risk_score == 0.7

    def test_multiple_tiers(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "baseline-allow", tier="baseline", effect="allow"),
            _rule(1, "org-deny", tier="org", effect="deny"),
        ])
        result = bdd.evaluate({0, 1})
        assert result.effect == "deny"
        assert result.denied_by == "org-deny"

    def test_matched_rule_ids_tracked(self) -> None:
        bdd = PolicyBDD([
            _rule(0, "r1", tier="baseline", effect="allow"),
            _rule(1, "r2", tier="app", effect="allow"),
        ])
        result = bdd.evaluate({0, 1})
        rule_ids = {rid for rid, _ in result.matched_rule_ids}
        assert "r1" in rule_ids
        assert "r2" in rule_ids

    def test_partial_match(self) -> None:
        """Only evaluate rules that actually matched."""
        bdd = PolicyBDD([
            _rule(0, "r1", effect="allow"),
            _rule(1, "r2", effect="deny"),
            _rule(2, "r3", effect="allow"),
        ])
        # Only r1 and r3 matched (not the deny rule)
        result = bdd.evaluate({0, 2})
        assert result.effect == "allow"
