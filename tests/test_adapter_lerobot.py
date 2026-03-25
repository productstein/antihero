"""Tests for LeRobot adapter."""

from __future__ import annotations

from uuid import uuid4

import pytest
from unittest.mock import MagicMock

from antihero.adapters.lerobot import LeRobotAdapter, _action_to_params, _build_context
from antihero.envelopes.pde import PolicyDecisionEnvelope
from antihero.exceptions import ActionDeniedError


class _FakePolicy:
    def select_action(self, observation: object, **kwargs: object) -> list[float]:
        return [0.1, 0.2, 0.3, 0.4]


def _make_pde(effect: str, reason: str = "") -> PolicyDecisionEnvelope:
    return PolicyDecisionEnvelope(tce_id=uuid4(), effect=effect, reason=reason)


class TestLeRobotAdapter:
    def test_enforce_allowed(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        adapter = LeRobotAdapter()
        # Should not raise
        adapter.enforce(guard, [0.1, 0.2, 0.3], agent_id="bot-1")

    def test_enforce_denied(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("deny", "Velocity exceeds limit")

        adapter = LeRobotAdapter()
        with pytest.raises(ActionDeniedError, match="Velocity exceeds"):
            adapter.enforce(guard, [0.1, 0.2, 0.3])

    def test_wrap_policy(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        policy = _FakePolicy()
        adapter = LeRobotAdapter()
        guarded = adapter.wrap_policy(policy, guard, agent_id="test-bot")
        result = guarded.select_action({"obs": [1, 2, 3]})

        assert result == [0.1, 0.2, 0.3, 0.4]
        guard.evaluate.assert_called_once()

    def test_wrap_policy_denied(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("deny", "Unsafe")

        policy = _FakePolicy()
        adapter = LeRobotAdapter()
        guarded = adapter.wrap_policy(policy, guard)

        with pytest.raises(ActionDeniedError):
            guarded.select_action({"obs": [1, 2, 3]})

    def test_detect_policy(self) -> None:
        adapter = LeRobotAdapter()
        assert adapter.detect(_FakePolicy())
        assert not adapter.detect("not_a_policy")

    def test_no_select_action(self) -> None:
        adapter = LeRobotAdapter()
        guard = MagicMock()
        with pytest.raises(ValueError, match="select_action"):
            adapter.wrap_policy("not_a_policy", guard)

    def test_observation_context_forwarded(self) -> None:
        guard = MagicMock()
        guard.evaluate.return_value = _make_pde("allow")

        adapter = LeRobotAdapter()
        obs = {"force": 25.0, "human_detected": True, "distance_to_human": 1.2}
        adapter.enforce(guard, [0.1], observation=obs)

        call_kwargs = guard.evaluate.call_args[1]
        assert call_kwargs["context"]["force"] == 25.0
        assert call_kwargs["context"]["human_detected"] is True


class TestHelpers:
    def test_action_to_params_list(self) -> None:
        result = _action_to_params([0.1, 0.2, 0.3])
        assert result["num_joints"] == 3
        assert result["joint_values"] == [0.1, 0.2, 0.3]

    def test_action_to_params_dict(self) -> None:
        result = _action_to_params({"joint1": 0.5})
        assert result == {"joint1": 0.5}

    def test_action_to_params_string(self) -> None:
        result = _action_to_params("unknown")
        assert "action" in result

    def test_build_context_with_observation(self) -> None:
        ctx = _build_context([0.1], {"force": 10.0, "velocity": 0.5, "unrelated": "x"})
        assert ctx["force"] == 10.0
        assert ctx["velocity"] == 0.5
        assert "unrelated" not in ctx
        assert ctx["caller_type"] == "lerobot"

    def test_build_context_no_observation(self) -> None:
        ctx = _build_context([0.1], None)
        assert ctx["caller_type"] == "lerobot"
