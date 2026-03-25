"""Tests for SimulationValidator with mock backends."""

from unittest.mock import patch

import pytest

from antihero.simulation.digital_twin.config import SimulationConfig
from antihero.simulation.digital_twin.result import SimulationResult, Violation
from antihero.simulation.digital_twin.validator import SimulationValidator


class TestSimulationConfig:
    """Test SimulationConfig model."""

    def test_defaults(self) -> None:
        cfg = SimulationConfig()
        assert cfg.engine == "mujoco"
        assert cfg.horizon_steps == 100
        assert cfg.max_contact_force == 50.0
        assert cfg.max_joint_effort == 80.0
        assert cfg.timeout_ms == 50.0

    def test_from_requirement_params(self) -> None:
        params = {
            "engine": "mujoco",
            "model_path": "robot.xml",
            "horizon_steps": 200,
            "max_contact_force": 30.0,
            "collision_whitelist": ["ground", "table"],
            "unknown_field": "ignored",
        }
        cfg = SimulationConfig.from_requirement_params(params)
        assert cfg.engine == "mujoco"
        assert cfg.model_path == "robot.xml"
        assert cfg.horizon_steps == 200
        assert cfg.max_contact_force == 30.0
        assert cfg.collision_whitelist == ["ground", "table"]

    def test_validation(self) -> None:
        with pytest.raises(Exception):
            SimulationConfig(horizon_steps=0)  # ge=1
        with pytest.raises(Exception):
            SimulationConfig(max_contact_force=-1)  # gt=0


class TestSimulationValidator:
    """Test validator dispatch and error handling."""

    def test_mujoco_dispatch(self) -> None:
        """Validator dispatches to mujoco_backend.validate()."""
        safe_result = SimulationResult(safe=True, sim_steps_completed=100)

        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            return_value=safe_result,
        ):
            validator = SimulationValidator()
            config = SimulationConfig(engine="mujoco", model_path="test.xml")
            result = validator.validate(config)
            assert result.safe

    def test_mujoco_unsafe(self) -> None:
        """Validator returns unsafe result from backend."""
        unsafe_result = SimulationResult(
            safe=False,
            violations=[
                Violation(
                    type="contact_force",
                    description="Force 60N exceeds 50N",
                    value=60.0,
                    limit=50.0,
                    step=42,
                )
            ],
        )

        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            return_value=unsafe_result,
        ):
            validator = SimulationValidator()
            config = SimulationConfig(engine="mujoco", model_path="test.xml")
            result = validator.validate(config)
            assert not result.safe
            assert len(result.violations) == 1

    def test_isaac_import_error_without_gpu(self) -> None:
        """Isaac backend fails closed when isaacsim not installed."""
        validator = SimulationValidator()
        config = SimulationConfig(engine="isaac")
        result = validator.validate(config)
        assert not result.safe
        assert result.violations[0].type == "backend_unavailable"

    def test_unknown_engine(self) -> None:
        """Unknown engine returns unsafe result."""
        validator = SimulationValidator()
        config = SimulationConfig(engine="unknown_engine")
        result = validator.validate(config)
        assert not result.safe
        assert result.violations[0].type == "unknown_engine"

    def test_import_error_fail_closed(self) -> None:
        """If mujoco package is missing, fail closed."""
        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            side_effect=ImportError("No module named 'mujoco'"),
        ):
            validator = SimulationValidator()
            config = SimulationConfig(engine="mujoco", model_path="test.xml")
            result = validator.validate(config)
            assert not result.safe
            assert result.violations[0].type == "backend_unavailable"

    def test_runtime_error_fail_closed(self) -> None:
        """If simulation crashes, fail closed."""
        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            side_effect=RuntimeError("Simulation exploded"),
        ):
            validator = SimulationValidator()
            config = SimulationConfig(engine="mujoco", model_path="test.xml")
            result = validator.validate(config)
            assert not result.safe
            assert result.violations[0].type == "simulation_error"

    def test_action_params_passed(self) -> None:
        """Action params are forwarded to the backend."""
        safe_result = SimulationResult(safe=True)
        received_params = {}

        def mock_validate(config, action_params=None):
            received_params["params"] = action_params
            return safe_result

        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            side_effect=mock_validate,
        ):
            validator = SimulationValidator()
            config = SimulationConfig(engine="mujoco", model_path="test.xml")
            params = {"ctrl": [0.5, 0.3], "joint_targets": {"elbow": 1.2}}
            validator.validate(config, params)
            assert received_params["params"] == params


class TestRequirementIntegration:
    """Test simulate requirement handler."""

    def test_simulate_requirement_safe(self) -> None:
        """Simulate requirement satisfied when sim is safe."""
        from antihero.envelopes.pde import Requirement
        from antihero.envelopes.tce import Subject, ToolCallEnvelope
        from antihero.policy.requirements import handle_requirement

        safe_result = SimulationResult(safe=True, sim_steps_completed=100)

        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            return_value=safe_result,
        ):
            tce = ToolCallEnvelope(
                subject=Subject(agent_id="bot-1"),
                action="motion.arm.move",
                resource="joint/elbow",
            )
            req = Requirement(
                kind="simulate",
                params={
                    "engine": "mujoco",
                    "model_path": "robot.xml",
                    "max_contact_force": 50.0,
                },
            )
            result = handle_requirement(req, tce)
            assert result.satisfied

    def test_simulate_requirement_unsafe(self) -> None:
        """Simulate requirement raises when sim is unsafe."""
        from antihero.envelopes.pde import Requirement
        from antihero.envelopes.tce import Subject, ToolCallEnvelope
        from antihero.exceptions import RequirementNotSatisfiedError
        from antihero.policy.requirements import handle_requirement

        unsafe_result = SimulationResult(
            safe=False,
            violations=[
                Violation(
                    type="contact_force",
                    description="Force 60N exceeds 50N",
                    value=60.0,
                    limit=50.0,
                    step=42,
                )
            ],
        )

        with patch(
            "antihero.simulation.digital_twin.mujoco_backend.validate",
            return_value=unsafe_result,
        ):
            tce = ToolCallEnvelope(
                subject=Subject(agent_id="bot-1"),
                action="motion.arm.move",
                resource="joint/elbow",
            )
            req = Requirement(
                kind="simulate",
                params={"engine": "mujoco", "model_path": "robot.xml"},
            )
            with pytest.raises(RequirementNotSatisfiedError, match="Force 60N"):
                handle_requirement(req, tce)
