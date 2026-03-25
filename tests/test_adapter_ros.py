"""Tests for ROS 2 adapter."""

from __future__ import annotations

from uuid import uuid4

import pytest
from unittest.mock import MagicMock

from antihero.adapters.ros import ROS2Adapter, _extract_goal_params
from antihero.envelopes.pde import PolicyDecisionEnvelope
from antihero.exceptions import ActionDeniedError


class _FakeGoalHandle:
    class _Request:
        __slots__ = ("target_position", "max_velocity")

        def __init__(self) -> None:
            self.target_position = 1.5
            self.max_velocity = 0.5

    request = _Request()


def _make_pde(effect: str, reason: str = "") -> PolicyDecisionEnvelope:
    return PolicyDecisionEnvelope(tce_id=uuid4(), effect=effect, reason=reason)


class TestROS2Adapter:
    def test_wrap_callback_allowed(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")
        original = MagicMock(return_value="result")

        adapter = ROS2Adapter()
        wrapped = adapter.wrap_callback(
            original, guard, action_name="motion.arm.move", agent_id="bot-1"
        )
        result = wrapped(_FakeGoalHandle())

        assert result == "result"
        original.assert_called_once()

    def test_wrap_callback_denied(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("deny", "Force too high")
        original = MagicMock()

        adapter = ROS2Adapter()
        wrapped = adapter.wrap_callback(
            original, guard, action_name="force.apply", agent_id="bot-1"
        )

        with pytest.raises(ActionDeniedError, match="Force too high"):
            wrapped(_FakeGoalHandle())

        original.assert_not_called()

    def test_check_action(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        adapter = ROS2Adapter()
        pde = adapter.check_action(guard, "motion.base.move", agent_id="nav-bot")

        assert pde.effect == "allow"
        guard.evaluate.assert_called_once()

    def test_detect_without_rclpy(self) -> None:
        adapter = ROS2Adapter()
        assert not adapter.detect("not_a_node")

    def test_extract_goal_params(self) -> None:
        handle = _FakeGoalHandle()
        params = _extract_goal_params(handle)
        assert params["target_position"] == 1.5
        assert params["max_velocity"] == 0.5

    def test_extract_goal_params_no_slots(self) -> None:
        handle = MagicMock()
        handle.request = "simple_string"
        params = _extract_goal_params(handle)
        assert "goal" in params

    def test_callback_name_preserved(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        def my_callback(goal: object) -> str:
            return "ok"

        adapter = ROS2Adapter()
        wrapped = adapter.wrap_callback(my_callback, guard, action_name="test")
        assert "antihero_guarded" in wrapped.__name__


class TestROS2AdapterContext:
    def test_context_passed_to_evaluate(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        adapter = ROS2Adapter()
        adapter.check_action(guard, "motion.arm.move", context={"zone": "A"})

        call_kwargs = guard.evaluate.call_args[1]
        assert call_kwargs["context"] == {"zone": "A"}

    def test_roles_passed(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        adapter = ROS2Adapter()
        adapter.check_action(
            guard,
            "motion.arm.move",
            roles=frozenset(["worker", "picker"]),
        )

        call_kwargs = guard.evaluate.call_args[1]
        assert "worker" in call_kwargs["subject"].roles
