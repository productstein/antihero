"""Tests for the policy compiler."""

import pytest

from antihero.policy.schema import PolicyCondition, PolicyDocument, PolicyRule
from antihero.realtime.compiler import PolicyCompiler


class TestPolicyCompiler:
    """Test policy compilation."""

    def test_compile_single_policy(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="r1", effect="allow", actions=["file.*"]),
                ],
            )
        ]
        compiler = PolicyCompiler(policies)
        artifact = compiler.compile()

        assert artifact.total_rules == 1
        assert artifact.tier_counts["app"] == 1
        assert artifact.policy_hash
        assert artifact.compiled_at > 0

    def test_compile_multi_tier(self) -> None:
        policies = [
            PolicyDocument(
                tier="baseline",
                name="base",
                rules=[PolicyRule(id="b1", effect="allow", actions=["*"])],
            ),
            PolicyDocument(
                tier="org",
                name="org",
                rules=[PolicyRule(id="o1", effect="deny", actions=["shell.*"])],
            ),
            PolicyDocument(
                tier="app",
                name="app",
                rules=[
                    PolicyRule(id="a1", effect="allow", actions=["file.*"]),
                    PolicyRule(id="a2", effect="deny", actions=["db.drop"]),
                ],
            ),
        ]
        compiler = PolicyCompiler(policies)
        artifact = compiler.compile()

        assert artifact.total_rules == 4
        assert artifact.tier_counts["baseline"] == 1
        assert artifact.tier_counts["org"] == 1
        assert artifact.tier_counts["app"] == 2

    def test_action_trie_populated(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="r1", effect="allow", actions=["file.*"]),
                    PolicyRule(id="r2", effect="deny", actions=["shell.*"]),
                ],
            )
        ]
        artifact = PolicyCompiler(policies).compile()

        # Action trie should find rules for file.write
        matches = artifact.action_trie.match("file.write")
        assert len(matches) >= 1

    def test_resource_trie_populated(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(
                        id="r1",
                        effect="allow",
                        actions=["file.*"],
                        resources=["data.*"],
                    ),
                ],
            )
        ]
        artifact = PolicyCompiler(policies).compile()

        assert artifact.resource_trie.match("data.output")
        assert not artifact.resource_trie.match("etc.passwd")

    def test_conditions_compiled(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(
                        id="r1",
                        effect="allow",
                        actions=["*"],
                        conditions=[
                            PolicyCondition(field="context.x", operator="gt", value=5),
                        ],
                    ),
                ],
            )
        ]
        artifact = PolicyCompiler(policies).compile()
        rule = artifact.rules[0]
        assert not rule.conditions.is_empty

    def test_subject_index_built(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(
                        id="r1",
                        effect="allow",
                        actions=["*"],
                        subjects=["admin-*"],
                    ),
                    PolicyRule(
                        id="r2",
                        effect="allow",
                        actions=["*"],
                        subjects=["*"],
                    ),
                ],
            )
        ]
        artifact = PolicyCompiler(policies).compile()

        assert "admin-*" in artifact.subject_index
        assert "*" in artifact.subject_index
        assert 0 in artifact.subject_index["admin-*"]
        assert 1 in artifact.subject_index["*"]

    def test_bdd_built(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="r1", effect="allow", actions=["*"]),
                    PolicyRule(id="r2", effect="deny", actions=["shell.*"]),
                ],
            )
        ]
        artifact = PolicyCompiler(policies).compile()

        # BDD should produce deny when both rules match
        result = artifact.bdd.evaluate({0, 1})
        assert result.effect == "deny"

    def test_priority_ordering(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="low", effect="allow", actions=["*"], priority=1),
                    PolicyRule(id="high", effect="allow", actions=["*"], priority=10),
                ],
            )
        ]
        artifact = PolicyCompiler(policies).compile()

        # Higher priority should be first
        assert artifact.rules[0].rule_id == "high"
        assert artifact.rules[1].rule_id == "low"

    def test_hash_deterministic(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[PolicyRule(id="r1", effect="allow", actions=["*"])],
            )
        ]
        h1 = PolicyCompiler(policies).compile().policy_hash
        h2 = PolicyCompiler(policies).compile().policy_hash
        assert h1 == h2

    def test_empty_policy_compiles(self) -> None:
        """Edge case: policy with one rule (minimum)."""
        policies = [
            PolicyDocument(
                tier="app",
                name="minimal",
                rules=[PolicyRule(id="r1", effect="deny", actions=["*"])],
            )
        ]
        artifact = PolicyCompiler(policies).compile()
        assert artifact.total_rules == 1
