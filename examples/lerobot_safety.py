"""LeRobot example: enforce safety on learned robot policies.

Shows how to wrap a LeRobot-trained policy with Antihero safety
enforcement. Every action output from the policy is checked against
safety rules before reaching the hardware.

Run: python examples/lerobot_safety.py
"""

from antihero.adapters.lerobot import LeRobotAdapter
from antihero.policy.schema import PolicyCondition, PolicyDocument, PolicyRule
from antihero.policy.engine import PolicyEngine
from antihero.envelopes.tce import Subject, ToolCallEnvelope
from antihero.exceptions import ActionDeniedError


class FakeLeRobotPolicy:
    """Simulates a LeRobot policy that outputs joint actions."""

    def select_action(self, observation, **kwargs):
        # Returns joint velocities — some safe, some not
        if observation.get("task") == "gentle_handoff":
            return [0.1, 0.05, 0.08, 0.02]  # Safe velocities
        elif observation.get("task") == "fast_grab":
            return [2.5, 3.0, 1.8, 2.2]  # Unsafe — too fast
        return [0.3, 0.2, 0.4, 0.1]  # Default safe


def main():
    # Define safety policy
    policy = PolicyDocument(
        version="1.0",
        tier="app",
        name="lerobot-safety",
        rules=[
            PolicyRule(
                id="allow-safe-motion",
                effect="allow",
                actions=["motion.joint.*"],
                risk_score=0.2,
            ),
            PolicyRule(
                id="deny-high-velocity",
                description="Block joint velocities above 2.0 m/s",
                effect="deny",
                actions=["motion.joint.*"],
                conditions=[
                    PolicyCondition(
                        field="context.max_joint_velocity",
                        operator="gt",
                        value=2.0,
                    ),
                ],
            ),
        ],
    )

    engine = PolicyEngine([policy])

    class SimpleGuard:
        def evaluate(self, **kwargs):
            tce = ToolCallEnvelope(
                subject=Subject(agent_id=kwargs.get("agent_id", "bot")),
                action=kwargs["action"],
                resource=kwargs.get("resource", "actuators"),
                parameters=kwargs.get("parameters", {}),
                context=kwargs.get("context", {}),
            )
            return engine.evaluate(tce)

    guard = SimpleGuard()
    adapter = LeRobotAdapter()
    lerobot_policy = FakeLeRobotPolicy()

    # Wrap the policy with safety enforcement
    safe_policy = adapter.wrap_policy(
        lerobot_policy,
        guard,
        agent_id="assembly-bot-01",
    )

    # Test 1: Gentle handoff — should pass
    print("Task: gentle_handoff")
    try:
        action = safe_policy.select_action({"task": "gentle_handoff"})
        print(f"  Action allowed: {action}")
    except ActionDeniedError as e:
        print(f"  BLOCKED: {e}")

    # Test 2: Fast grab — should be blocked
    print("\nTask: fast_grab")
    try:
        action = safe_policy.select_action({"task": "fast_grab"})
        print(f"  Action allowed: {action}")
    except ActionDeniedError as e:
        print(f"  BLOCKED: {e}")

    # Test 3: Default — should pass
    print("\nTask: default")
    try:
        action = safe_policy.select_action({"task": "default"})
        print(f"  Action allowed: {action}")
    except ActionDeniedError as e:
        print(f"  BLOCKED: {e}")


if __name__ == "__main__":
    main()
