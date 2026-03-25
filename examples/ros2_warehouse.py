"""ROS 2 example: wrap an action server callback with safety enforcement.

This example shows how to use the Antihero ROS 2 adapter to intercept
robot actions before they execute. The adapter checks every action
against your safety policies and blocks unsafe ones.

Note: This example uses mocks since rclpy requires a ROS 2 installation.
In a real ROS 2 project, replace the mocks with actual rclpy imports.

Run: python examples/ros2_warehouse.py
"""

from unittest.mock import MagicMock

from antihero.adapters.ros import ROS2Adapter
from antihero.policy.schema import PolicyCondition, PolicyDocument, PolicyRule
from antihero.policy.engine import PolicyEngine
from antihero.envelopes.pde import PolicyDecisionEnvelope
from antihero.envelopes.tce import Subject, ToolCallEnvelope


def main():
    # Define warehouse robot safety policy
    policy = PolicyDocument(
        version="1.0",
        tier="app",
        name="warehouse-ros2",
        rules=[
            PolicyRule(
                id="allow-pick",
                effect="allow",
                actions=["motion.arm.*"],
                risk_score=0.2,
            ),
            PolicyRule(
                id="deny-fast-motion",
                description="Block motion faster than 1.5 m/s",
                effect="deny",
                actions=["motion.*"],
                conditions=[
                    PolicyCondition(
                        field="context.velocity_mps",
                        operator="gt",
                        value=1.5,
                    ),
                ],
            ),
            PolicyRule(
                id="allow-navigation",
                effect="allow",
                actions=["motion.base.*"],
                risk_score=0.1,
            ),
        ],
    )

    # Create a mock Guard that uses the policy engine
    engine = PolicyEngine([policy])

    class SimpleGuard:
        def evaluate(self, **kwargs):
            tce = ToolCallEnvelope(
                subject=Subject(agent_id=kwargs.get("agent_id", "bot")),
                action=kwargs["action"],
                resource=kwargs.get("resource", "ros2"),
                parameters=kwargs.get("parameters", {}),
                context=kwargs.get("context", {}),
            )
            return engine.evaluate(tce)

    guard = SimpleGuard()
    adapter = ROS2Adapter()

    # Check a safe navigation action
    print("Checking: motion.base.navigate at 0.5 m/s...")
    pde = adapter.check_action(
        guard,
        action_name="motion.base.navigate",
        resource="floor.zone_A",
        agent_id="warehouse-bot-01",
        context={"velocity_mps": 0.5},
    )
    print(f"  Result: {pde.effect} — {pde.reason}")

    # Check an unsafe fast motion
    print("\nChecking: motion.base.navigate at 2.0 m/s...")
    pde2 = adapter.check_action(
        guard,
        action_name="motion.base.navigate",
        resource="floor.zone_B",
        agent_id="warehouse-bot-01",
        context={"velocity_mps": 2.0},
    )
    print(f"  Result: {pde2.effect} — {pde2.reason}")

    # Check arm motion (allowed)
    print("\nChecking: motion.arm.move...")
    pde3 = adapter.check_action(
        guard,
        action_name="motion.arm.move",
        resource="joint.left-elbow",
        agent_id="warehouse-bot-01",
        context={"velocity_mps": 0.8},
    )
    print(f"  Result: {pde3.effect} — {pde3.reason}")


if __name__ == "__main__":
    main()
