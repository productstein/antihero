"""End-to-end tests: compiled evaluator must produce identical decisions to interpreted engine."""

import pytest

from antihero.envelopes.tce import Subject, ToolCallEnvelope
from antihero.policy.engine import PolicyEngine
from antihero.policy.schema import PolicyCondition, PolicyDocument, PolicyRule
from antihero.realtime.compiler import PolicyCompiler
from antihero.realtime.evaluator import CompiledEvaluator
from antihero.realtime.subject import CompiledSubject


def _make_tce(
    action: str = "file.write",
    resource: str = "/data/output.txt",
    agent_id: str = "bot-1",
    roles: frozenset[str] | None = None,
) -> ToolCallEnvelope:
    return ToolCallEnvelope(
        subject=Subject(
            agent_id=agent_id,
            roles=roles or frozenset(),
        ),
        action=action,
        resource=resource,
    )


def _make_subject(
    agent_id: str = "bot-1",
    roles: frozenset[str] | None = None,
) -> CompiledSubject:
    return CompiledSubject.create(agent_id=agent_id, roles=roles or frozenset())


class TestCompiledVsInterpreted:
    """Ensure compiled engine produces identical decisions to interpreted."""

    def _assert_same_effect(
        self,
        policies: list[PolicyDocument],
        action: str,
        resource: str,
        agent_id: str = "bot-1",
        roles: frozenset[str] | None = None,
    ) -> None:
        """Helper: check that compiled and interpreted produce same effect."""
        # Interpreted
        engine = PolicyEngine(policies)
        tce = _make_tce(action, resource, agent_id, roles)
        interpreted = engine.evaluate(tce)

        # Compiled
        compiler = PolicyCompiler(policies)
        artifact = compiler.compile()
        evaluator = CompiledEvaluator(artifact)
        subject = _make_subject(agent_id, roles)
        compiled = evaluator.evaluate(action, resource, subject)

        assert compiled.effect == interpreted.effect, (
            f"Effect mismatch: compiled={compiled.effect}, "
            f"interpreted={interpreted.effect} "
            f"for action={action}, resource={resource}"
        )

    def test_simple_allow(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="r1", effect="allow", actions=["file.*"]),
                ],
            )
        ]
        self._assert_same_effect(policies, "file.write", "/data/out.txt")

    def test_simple_deny(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="r1", effect="deny", actions=["shell.*"]),
                ],
            )
        ]
        self._assert_same_effect(policies, "shell.execute", "/bin/bash")

    def test_no_match_fail_closed(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="r1", effect="allow", actions=["file.*"]),
                ],
            )
        ]
        self._assert_same_effect(policies, "db.query", "users")

    def test_deny_dominates(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="allow-all", effect="allow", actions=["*"]),
                    PolicyRule(id="deny-shell", effect="deny", actions=["shell.*"]),
                ],
            )
        ]
        self._assert_same_effect(policies, "shell.execute", "/bin/bash")

    def test_allow_with_requirements(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(
                        id="gated",
                        effect="allow_with_requirements",
                        actions=["db.*"],
                        requirements=[{"kind": "mfa"}],
                    ),
                ],
            )
        ]
        self._assert_same_effect(policies, "db.delete", "users")

    def test_multi_tier(self) -> None:
        policies = [
            PolicyDocument(
                tier="baseline",
                name="base",
                rules=[
                    PolicyRule(id="base-allow", effect="allow", actions=["*"]),
                ],
            ),
            PolicyDocument(
                tier="org",
                name="org",
                rules=[
                    PolicyRule(id="org-deny", effect="deny", actions=["shell.*"]),
                ],
            ),
        ]
        self._assert_same_effect(policies, "shell.execute", "/bin/bash")
        self._assert_same_effect(policies, "file.write", "/data/out.txt")

    def test_with_conditions(self) -> None:
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
                            PolicyCondition(
                                field="subject.agent_id",
                                operator="eq",
                                value="bot-1",
                            ),
                        ],
                    ),
                ],
            )
        ]
        self._assert_same_effect(policies, "file.write", "/data/out.txt", "bot-1")
        self._assert_same_effect(policies, "file.write", "/data/out.txt", "bot-2")

    def test_robotics_scenario(self) -> None:
        """Realistic robotics policy: motion allowed, force limited."""
        policies = [
            PolicyDocument(
                tier="baseline",
                name="robot-safety",
                rules=[
                    PolicyRule(
                        id="allow-motion",
                        effect="allow",
                        actions=["motion.*"],
                        risk_score=0.1,
                    ),
                    PolicyRule(
                        id="deny-force-exceed",
                        effect="deny",
                        actions=["force.*"],
                        conditions=[
                            PolicyCondition(
                                field="context.force_newtons",
                                operator="gt",
                                value=50.0,
                            ),
                        ],
                    ),
                    PolicyRule(
                        id="allow-force-safe",
                        effect="allow",
                        actions=["force.*"],
                        conditions=[
                            PolicyCondition(
                                field="context.force_newtons",
                                operator="lte",
                                value=50.0,
                            ),
                        ],
                        risk_score=0.3,
                    ),
                    PolicyRule(
                        id="deny-shutdown",
                        effect="deny",
                        actions=["power.shutdown"],
                        subjects=["*"],
                    ),
                ],
            )
        ]
        self._assert_same_effect(policies, "motion.arm.move", "joint/left-elbow")
        self._assert_same_effect(policies, "power.shutdown", "main-bus")


class TestCompiledEvaluator:
    """Direct tests of the compiled evaluator."""

    def test_catch_all_deny(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(id="deny-all", effect="deny", actions=["*"]),
                ],
            )
        ]
        compiler = PolicyCompiler(policies)
        artifact = compiler.compile()
        evaluator = CompiledEvaluator(artifact)
        subject = _make_subject()

        result = evaluator.evaluate("anything", "anywhere", subject)
        assert result.effect == "deny"
        assert result.denied_by == "deny-all"

    def test_subject_filtering(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(
                        id="admin-only",
                        effect="allow",
                        actions=["*"],
                        subjects=["admin-*"],
                    ),
                ],
            )
        ]
        compiler = PolicyCompiler(policies)
        artifact = compiler.compile()
        evaluator = CompiledEvaluator(artifact)

        admin = CompiledSubject.create(agent_id="admin-bot")
        user = CompiledSubject.create(agent_id="user-bot")

        assert evaluator.evaluate("file.write", "/data", admin).effect == "allow"
        assert evaluator.evaluate("file.write", "/data", user).effect == "deny"

    def test_resource_matching(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[
                    PolicyRule(
                        id="allow-data",
                        effect="allow",
                        actions=["file.*"],
                        resources=["data.*"],
                    ),
                    PolicyRule(
                        id="deny-etc",
                        effect="deny",
                        actions=["file.*"],
                        resources=["etc.*"],
                    ),
                ],
            )
        ]
        compiler = PolicyCompiler(policies)
        artifact = compiler.compile()
        evaluator = CompiledEvaluator(artifact)
        subject = _make_subject()

        assert evaluator.evaluate("file.write", "data.output", subject).effect == "allow"
        assert evaluator.evaluate("file.write", "etc.passwd", subject).effect == "deny"

    def test_policy_hash_stable(self) -> None:
        policies = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[PolicyRule(id="r1", effect="allow", actions=["*"])],
            )
        ]
        c1 = PolicyCompiler(policies).compile()
        c2 = PolicyCompiler(policies).compile()
        assert c1.policy_hash == c2.policy_hash

    def test_policy_hash_changes(self) -> None:
        p1 = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[PolicyRule(id="r1", effect="allow", actions=["*"])],
            )
        ]
        p2 = [
            PolicyDocument(
                tier="app",
                name="test",
                rules=[PolicyRule(id="r1", effect="deny", actions=["*"])],
            )
        ]
        c1 = PolicyCompiler(p1).compile()
        c2 = PolicyCompiler(p2).compile()
        assert c1.policy_hash != c2.policy_hash
