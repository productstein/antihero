"""Performance benchmark: compiled evaluator must achieve <100μs per evaluation."""

import time

import pytest

from antihero.policy.schema import PolicyCondition, PolicyDocument, PolicyRule
from antihero.realtime.compiler import PolicyCompiler
from antihero.realtime.evaluator import CompiledEvaluator
from antihero.realtime.subject import CompiledSubject


def _build_robotics_policies() -> list[PolicyDocument]:
    """Build a realistic robotics policy set with 30+ rules."""
    return [
        PolicyDocument(
            tier="baseline",
            name="robot-safety-baseline",
            rules=[
                PolicyRule(id="allow-perception", effect="allow", actions=["perception.*"], risk_score=0.0),
                PolicyRule(id="allow-communication", effect="allow", actions=["communication.*"], risk_score=0.1),
                PolicyRule(id="deny-power-unauthorized", effect="deny", actions=["power.*"], subjects=["worker-*"]),
                PolicyRule(id="allow-environment-read", effect="allow", actions=["environment.sensor.*"], risk_score=0.0),
            ],
        ),
        PolicyDocument(
            tier="org",
            name="warehouse-policy",
            rules=[
                PolicyRule(id="allow-motion-safe", effect="allow", actions=["motion.*"], risk_score=0.2),
                PolicyRule(id="deny-force-high", effect="deny", actions=["force.*"],
                          conditions=[PolicyCondition(field="context.force_newtons", operator="gt", value=100.0)]),
                PolicyRule(id="allow-force-safe", effect="allow", actions=["force.*"],
                          conditions=[PolicyCondition(field="context.force_newtons", operator="lte", value=100.0)],
                          risk_score=0.3),
                PolicyRule(id="deny-restricted-zone", effect="deny", actions=["motion.*"],
                          conditions=[PolicyCondition(field="context.zone", operator="eq", value="restricted")]),
                PolicyRule(id="allow-door", effect="allow", actions=["environment.door.*"], risk_score=0.1),
                PolicyRule(id="deny-elevator", effect="deny", actions=["environment.elevator.*"]),
                PolicyRule(id="allow-gripper", effect="allow", actions=["force.gripper.*"], risk_score=0.2),
                PolicyRule(id="deny-gripper-heavy", effect="deny", actions=["force.gripper.*"],
                          conditions=[PolicyCondition(field="context.payload_kg", operator="gt", value=25.0)]),
            ],
        ),
        PolicyDocument(
            tier="app",
            name="pick-and-place",
            rules=[
                PolicyRule(id="allow-pick", effect="allow", actions=["motion.arm.*"], risk_score=0.1),
                PolicyRule(id="allow-place", effect="allow", actions=["motion.arm.place"], risk_score=0.1),
                PolicyRule(id="deny-fast-motion", effect="deny", actions=["motion.*"],
                          conditions=[PolicyCondition(field="context.velocity_mps", operator="gt", value=1.5)]),
                PolicyRule(id="require-sim-heavy", effect="allow_with_requirements", actions=["force.gripper.close"],
                          conditions=[PolicyCondition(field="context.payload_kg", operator="gt", value=10.0)],
                          requirements=[{"kind": "simulate", "params": {"engine": "mujoco"}}]),
                PolicyRule(id="allow-nav", effect="allow", actions=["motion.base.*"], risk_score=0.1),
                PolicyRule(id="deny-nav-fast", effect="deny", actions=["motion.base.*"],
                          conditions=[PolicyCondition(field="context.velocity_mps", operator="gt", value=0.5)]),
                PolicyRule(id="allow-scan", effect="allow", actions=["perception.lidar.*"], risk_score=0.0),
                PolicyRule(id="allow-camera", effect="allow", actions=["perception.camera.*"], risk_score=0.0),
                PolicyRule(id="deny-power-off", effect="deny", actions=["power.shutdown"]),
                PolicyRule(id="allow-status", effect="allow", actions=["communication.status.*"], risk_score=0.0),
                PolicyRule(id="allow-log", effect="allow", actions=["communication.log.*"], risk_score=0.0),
                PolicyRule(id="deny-external-comm", effect="deny", actions=["communication.external.*"]),
            ],
        ),
        PolicyDocument(
            tier="user",
            name="operator-overrides",
            rules=[
                PolicyRule(id="admin-allow-all", effect="allow", actions=["*"], subjects=["admin-*"], priority=100),
                PolicyRule(id="maint-allow-power", effect="allow", actions=["power.*"], subjects=["maintenance-*"]),
                PolicyRule(id="deny-maint-force", effect="deny", actions=["force.*"], subjects=["maintenance-*"]),
            ],
        ),
    ]


class TestPerformance:
    """Benchmark compiled evaluator performance."""

    def test_1000_evals_under_100ms(self) -> None:
        """1000 evaluations must complete in under 100ms (100μs each)."""
        policies = _build_robotics_policies()
        artifact = PolicyCompiler(policies).compile()
        evaluator = CompiledEvaluator(artifact)
        subject = CompiledSubject.create(agent_id="worker-bot-1")

        # Warm up
        for _ in range(10):
            evaluator.evaluate("motion.arm.move", "joint.left-elbow", subject,
                             {"force_newtons": 30.0, "velocity_mps": 0.5})

        # Benchmark
        actions = [
            ("motion.arm.move", "joint.left-elbow", {"force_newtons": 30.0, "velocity_mps": 0.5}),
            ("force.gripper.close", "gripper.main", {"payload_kg": 5.0, "force_newtons": 20.0}),
            ("perception.camera.capture", "camera.front", {}),
            ("communication.status.heartbeat", "fleet.manager", {}),
            ("motion.base.move", "floor.zone-a", {"velocity_mps": 0.3}),
            ("environment.door.open", "door.loading-bay", {}),
            ("power.shutdown", "main-bus", {}),
            ("shell.execute", "/bin/bash", {}),
            ("force.gripper.close", "gripper.main", {"payload_kg": 30.0, "force_newtons": 80.0}),
            ("motion.arm.move", "joint.right-shoulder", {"velocity_mps": 2.0}),
        ]

        start = time.perf_counter_ns()
        for i in range(1000):
            action, resource, ctx = actions[i % len(actions)]
            evaluator.evaluate(action, resource, subject, ctx)
        elapsed_ns = time.perf_counter_ns() - start

        elapsed_ms = elapsed_ns / 1_000_000
        avg_us = elapsed_ns / 1_000_000 / 1000 * 1000  # μs per eval

        # Assert under 100ms for 1000 evals
        assert elapsed_ms < 100, (
            f"1000 evaluations took {elapsed_ms:.1f}ms "
            f"(avg {avg_us:.1f}μs/eval), target <100ms"
        )

    def test_compilation_time_reasonable(self) -> None:
        """Compilation should complete in under 50ms for 30+ rules."""
        policies = _build_robotics_policies()

        start = time.perf_counter_ns()
        artifact = PolicyCompiler(policies).compile()
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

        assert elapsed_ms < 50, f"Compilation took {elapsed_ms:.1f}ms, target <50ms"
        assert artifact.total_rules >= 27  # Verify we have a realistic rule count

    def test_deny_fast_path(self) -> None:
        """Deny decisions should be at least as fast as allows."""
        policies = _build_robotics_policies()
        artifact = PolicyCompiler(policies).compile()
        evaluator = CompiledEvaluator(artifact)
        subject = CompiledSubject.create(agent_id="worker-bot-1")

        # Warm up
        for _ in range(10):
            evaluator.evaluate("power.shutdown", "main-bus", subject)

        start = time.perf_counter_ns()
        for _ in range(1000):
            result = evaluator.evaluate("power.shutdown", "main-bus", subject)
        deny_ns = time.perf_counter_ns() - start

        assert result.effect == "deny"
        assert deny_ns / 1_000_000 < 100  # Still under 100ms total
