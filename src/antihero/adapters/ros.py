"""ROS 2 adapter — intercept action server and service calls with policy enforcement.

Wraps ROS 2 action server callbacks and service handlers with Antihero
policy evaluation.  Since ``rclpy`` is not pip-installable (it ships with
a ROS 2 workspace), all ROS imports are lazy and handle ImportError
gracefully.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Subject, ToolCallEnvelope
from antihero.exceptions import ActionDeniedError
from antihero.guard import Guard

logger = logging.getLogger(__name__)


class ROS2Adapter(ToolAdapter):
    """Wraps ROS 2 action servers and services with Antihero policy enforcement.

    Usage::

        from antihero.adapters.ros import ROS2Adapter

        adapter = ROS2Adapter()
        guarded_callback = adapter.wrap_callback(
            original_callback, guard,
            action_name="motion.arm.move",
            agent_id="warehouse-bot-1",
        )
    """

    def detect(self, agent: Any) -> bool:
        """Check if *agent* is a ROS 2 node or action server."""
        try:
            import rclpy.node  # type: ignore[import-untyped]

            return isinstance(agent, rclpy.node.Node)
        except ImportError:
            return False

    def wrap(self, agent: Any, guard: Guard) -> Any:
        """Wrap a ROS 2 node — returns the node unchanged.

        Node-level wrapping is done per-callback via :meth:`wrap_callback`.
        """
        return agent

    def wrap_callback(
        self,
        callback: Callable,
        guard: Guard,
        *,
        action_name: str,
        resource: str = "ros2",
        agent_id: str = "ros2-node",
        roles: frozenset[str] | None = None,
    ) -> Callable:
        """Wrap an action server execute_callback with policy enforcement.

        The wrapped callback evaluates policy BEFORE calling the original.
        If denied, it raises :class:`ActionDeniedError` (the caller should
        treat this as an aborted goal).
        """

        def guarded_callback(goal_handle: Any) -> Any:
            tce = ToolCallEnvelope(
                subject=Subject(
                    agent_id=agent_id,
                    roles=roles or frozenset(),
                ),
                action=action_name,
                resource=resource,
                parameters=_extract_goal_params(goal_handle),
                context={"caller_type": "ros2"},
            )

            pde = guard.evaluate(
                action=tce.action,
                resource=tce.resource,
                parameters=tce.parameters,
                subject=tce.subject,
                context=tce.context,
            )

            if pde.effect == "deny":
                logger.warning(
                    "ROS 2 action denied: %s on %s — %s",
                    action_name,
                    resource,
                    pde.reason,
                )
                raise ActionDeniedError(
                    f"Action '{action_name}' denied by policy: {pde.reason}",
                    pde=pde,
                )

            # Policy allows — execute original callback
            return callback(goal_handle)

        guarded_callback.__name__ = f"antihero_guarded_{getattr(callback, '__name__', 'callback')}"
        guarded_callback.__doc__ = f"Antihero-guarded ROS 2 callback for {action_name}"
        return guarded_callback

    def check_action(
        self,
        guard: Guard,
        action_name: str,
        resource: str = "ros2",
        agent_id: str = "ros2-node",
        roles: frozenset[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Standalone policy check without wrapping a callback.

        Returns the :class:`PolicyDecisionEnvelope`.  Useful for checking
        policy before submitting a goal.
        """
        return guard.evaluate(
            action=action_name,
            resource=resource,
            subject=Subject(
                agent_id=agent_id,
                roles=roles or frozenset(),
            ),
            context=context or {},
        )


def _extract_goal_params(goal_handle: Any) -> dict[str, Any]:
    """Extract parameters from a ROS 2 goal handle."""
    try:
        request = goal_handle.request
        # Convert ROS message to dict if it exposes __slots__
        if hasattr(request, "__slots__"):
            return {
                slot: getattr(request, slot)
                for slot in request.__slots__
                if not slot.startswith("_")
            }
        return {"goal": str(request)}
    except Exception:
        return {}
