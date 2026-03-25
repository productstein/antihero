"""LeRobot adapter — enforce safety policies on learned robot behaviors.

Sits between a trained LeRobot policy and the hardware actuators,
intercepting action outputs and checking them against safety policies
before they reach the robot.
"""

from __future__ import annotations

import logging
from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Subject, ToolCallEnvelope
from antihero.exceptions import ActionDeniedError
from antihero.guard import Guard

logger = logging.getLogger(__name__)


class LeRobotAdapter(ToolAdapter):
    """Wraps LeRobot policy inference with Antihero safety enforcement.

    Intercepts every ``select_action`` call on a LeRobot policy and
    evaluates the resulting action vector against Antihero safety
    policies before it reaches the robot's actuators.

    Usage::

        from antihero.adapters.lerobot import LeRobotAdapter

        adapter = LeRobotAdapter()
        safe_policy = adapter.wrap_policy(policy, guard, agent_id="my-robot")
        action = safe_policy.select_action(observation)
    """

    def detect(self, agent: Any) -> bool:
        """Check if *agent* is a LeRobot policy."""
        return hasattr(agent, "select_action") or hasattr(agent, "forward")

    def wrap(self, agent: Any, guard: Guard) -> Any:
        """Wrap a LeRobot policy with safety enforcement."""
        return self.wrap_policy(agent, guard)

    def wrap_policy(
        self,
        policy: Any,
        guard: Guard,
        *,
        agent_id: str = "lerobot-agent",
        roles: frozenset[str] | None = None,
        action_prefix: str = "motion.joint",
    ) -> Any:
        """Wrap a LeRobot policy so every action output is checked.

        Returns a wrapper object with the same ``select_action`` interface.
        """
        original_select = getattr(policy, "select_action", None) or getattr(
            policy, "forward", None
        )
        if original_select is None:
            raise ValueError("Policy must have 'select_action' or 'forward' method")

        adapter = self

        class GuardedPolicy:
            """LeRobot policy with Antihero safety enforcement."""

            def __init__(self) -> None:
                self._policy = policy
                self._guard = guard
                self._agent_id = agent_id
                self._roles = roles or frozenset()
                self._action_prefix = action_prefix

            def select_action(self, observation: Any, **kwargs: Any) -> Any:
                """Select action with safety check."""
                action = original_select(observation, **kwargs)
                adapter.enforce(
                    guard=guard,
                    action_output=action,
                    observation=observation,
                    agent_id=agent_id,
                    roles=roles,
                    action_prefix=action_prefix,
                )
                return action

            def __getattr__(self, name: str) -> Any:
                return getattr(policy, name)

        return GuardedPolicy()

    def enforce(
        self,
        guard: Guard,
        action_output: Any,
        observation: Any = None,
        agent_id: str = "lerobot-agent",
        roles: frozenset[str] | None = None,
        action_prefix: str = "motion.joint",
    ) -> None:
        """Check a LeRobot policy output against safety policies.

        Args:
            guard: Antihero Guard instance.
            action_output: Action from the policy (numpy array or dict).
            observation: Current observation for context.
            agent_id: Robot identifier.
            roles: Robot roles.
            action_prefix: Action name prefix (default: ``motion.joint``).

        Raises:
            ActionDeniedError: If the action violates safety policy.
        """
        context = _build_context(action_output, observation)

        pde = guard.evaluate(
            action=f"{action_prefix}.execute",
            resource="actuators",
            parameters=_action_to_params(action_output),
            subject=Subject(
                agent_id=agent_id,
                roles=roles or frozenset(),
            ),
            context=context,
        )

        if pde.effect == "deny":
            logger.warning(
                "LeRobot action denied for %s: %s",
                agent_id,
                pde.reason,
            )
            raise ActionDeniedError(
                f"LeRobot action denied by policy: {pde.reason}",
                pde=pde,
            )


def _action_to_params(action: Any) -> dict[str, Any]:
    """Convert LeRobot action output to parameters dict."""
    try:
        import numpy as np

        if isinstance(action, np.ndarray):
            return {
                "joint_values": action.tolist(),
                "num_joints": len(action),
                "max_value": float(action.max()),
                "min_value": float(action.min()),
            }
    except ImportError:
        pass

    if isinstance(action, dict):
        return action
    if isinstance(action, (list, tuple)):
        return {"joint_values": list(action), "num_joints": len(action)}
    return {"action": str(action)}


def _build_context(action: Any, observation: Any) -> dict[str, Any]:
    """Build context dict from action and observation for policy conditions."""
    context: dict[str, Any] = {"caller_type": "lerobot"}

    # Compute velocity stats from action output
    if isinstance(action, (list, tuple)):
        abs_vals = [abs(float(v)) for v in action]
        if abs_vals:
            context["max_joint_velocity"] = max(abs_vals)
            context["mean_joint_velocity"] = sum(abs_vals) / len(abs_vals)
    else:
        try:
            import numpy as np

            if isinstance(action, np.ndarray):
                context["max_joint_velocity"] = float(np.abs(action).max())
                context["mean_joint_velocity"] = float(np.abs(action).mean())
        except ImportError:
            pass

    if isinstance(observation, dict):
        for key in ("force", "velocity", "position", "human_detected", "distance_to_human"):
            if key in observation:
                context[key] = observation[key]

    return context
