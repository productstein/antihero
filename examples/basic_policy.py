"""Basic example: define a safety policy and evaluate robot actions.

Run: python examples/basic_policy.py
"""

from antihero.policy.schema import PolicyCondition, PolicyDocument, PolicyRule
from antihero.policy.engine import PolicyEngine
from antihero.envelopes.tce import Subject, ToolCallEnvelope


def main():
    # Define a safety policy for a warehouse robot
    policy = PolicyDocument(
        version="1.0",
        tier="app",
        name="warehouse-safety",
        rules=[
            PolicyRule(
                id="allow-motion",
                description="Allow all motion actions",
                effect="allow",
                actions=["motion.*"],
                risk_score=0.2,
            ),
            PolicyRule(
                id="deny-excessive-force",
                description="Block force above 50 Newtons",
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
                id="allow-safe-force",
                description="Allow force under 50 Newtons",
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
                description="Block power shutdown for non-maintenance roles",
                effect="deny",
                actions=["power.shutdown"],
            ),
        ],
    )

    engine = PolicyEngine([policy])

    # Test 1: Motion action — should be ALLOWED
    tce1 = ToolCallEnvelope(
        subject=Subject(agent_id="warehouse-bot-01"),
        action="motion.arm.move",
        resource="workspace.zone_A",
        context={"velocity_mps": 0.4},
    )
    result1 = engine.evaluate(tce1)
    print(f"motion.arm.move → {result1.effect} ({result1.reason})")

    # Test 2: Safe force — should be ALLOWED
    tce2 = ToolCallEnvelope(
        subject=Subject(agent_id="warehouse-bot-01"),
        action="force.gripper.close",
        resource="gripper.main",
        context={"force_newtons": 30.0},
    )
    result2 = engine.evaluate(tce2)
    print(f"force.gripper (30N) → {result2.effect} ({result2.reason})")

    # Test 3: Excessive force — should be DENIED
    tce3 = ToolCallEnvelope(
        subject=Subject(agent_id="warehouse-bot-01"),
        action="force.gripper.close",
        resource="gripper.main",
        context={"force_newtons": 75.0},
    )
    result3 = engine.evaluate(tce3)
    print(f"force.gripper (75N) → {result3.effect} ({result3.reason})")

    # Test 4: Power shutdown — should be DENIED
    tce4 = ToolCallEnvelope(
        subject=Subject(agent_id="warehouse-bot-01"),
        action="power.shutdown",
        resource="power.main-bus",
    )
    result4 = engine.evaluate(tce4)
    print(f"power.shutdown → {result4.effect} ({result4.reason})")

    # Test 5: Unknown action — should be DENIED (fail-closed)
    tce5 = ToolCallEnvelope(
        subject=Subject(agent_id="warehouse-bot-01"),
        action="network.external.transmit",
        resource="network.wan",
    )
    result5 = engine.evaluate(tce5)
    print(f"network.transmit → {result5.effect} ({result5.reason})")


if __name__ == "__main__":
    main()
