"""Tests for SimulationResult and Violation."""

import pytest

from antihero.simulation.digital_twin.result import SimulationResult, Violation


class TestViolation:
    """Test Violation dataclass."""

    def test_create(self) -> None:
        v = Violation(
            type="contact_force",
            description="Force 60N exceeds limit 50N",
            value=60.0,
            limit=50.0,
            step=42,
            body="arm<->table",
        )
        assert v.type == "contact_force"
        assert v.value == 60.0
        assert v.step == 42

    def test_frozen(self) -> None:
        v = Violation(type="x", description="y", value=1.0, limit=2.0, step=0)
        with pytest.raises(AttributeError):
            v.type = "z"  # type: ignore[misc]


class TestSimulationResult:
    """Test SimulationResult."""

    def test_safe_result(self) -> None:
        r = SimulationResult(
            safe=True,
            max_contact_force=30.0,
            max_joint_effort_pct=45.0,
            sim_steps_completed=100,
            sim_time_ms=12.5,
        )
        assert r.safe
        assert "SAFE" in r.summary
        assert r.to_dict()["safe"] is True

    def test_unsafe_result(self) -> None:
        v = Violation(
            type="contact_force",
            description="Force exceeded",
            value=60.0,
            limit=50.0,
            step=42,
        )
        r = SimulationResult(safe=False, violations=[v])
        assert not r.safe
        assert "UNSAFE" in r.summary
        assert len(r.to_dict()["violations"]) == 1

    def test_to_dict_complete(self) -> None:
        r = SimulationResult(
            safe=True,
            max_contact_force=10.0,
            max_joint_effort_pct=20.0,
            max_velocity=0.5,
            total_contacts=3,
            sim_steps_completed=100,
            sim_time_ms=5.0,
            engine="mujoco",
        )
        d = r.to_dict()
        assert d["engine"] == "mujoco"
        assert d["total_contacts"] == 3
        assert d["max_velocity"] == 0.5
        assert d["violations"] == []

    def test_multiple_violations(self) -> None:
        violations = [
            Violation(type="contact_force", description="f1", value=60, limit=50, step=10),
            Violation(type="velocity", description="v1", value=3.0, limit=2.0, step=20),
            Violation(type="collision", description="c1", value=5.0, limit=0, step=30),
        ]
        r = SimulationResult(safe=False, violations=violations)
        assert "3 violation(s)" in r.summary
        assert "contact_force" in r.summary
