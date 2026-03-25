"""Tests for ISO 13482 certification scenario suite."""

import pytest

from antihero.simulation.scenarios import get_suite, get_all_suites
from antihero.simulation.suites.iso_13482 import ISO_13482_SUITE


class TestISO13482Suite:
    """Validate the ISO 13482 scenario suite."""

    def test_suite_has_30_plus_scenarios(self) -> None:
        assert ISO_13482_SUITE.scenario_count >= 30

    def test_suite_id(self) -> None:
        assert ISO_13482_SUITE.id == "iso_13482"

    def test_suite_discoverable(self) -> None:
        """Suite is registered and discoverable via get_suite()."""
        suite = get_suite("iso_13482")
        assert suite is not None
        assert suite.id == "iso_13482"

    def test_suite_in_all_suites(self) -> None:
        all_suites = get_all_suites()
        ids = [s.id for s in all_suites]
        assert "iso_13482" in ids

    def test_has_benign_scenarios(self) -> None:
        assert ISO_13482_SUITE.benign_count >= 10

    def test_has_adversarial_scenarios(self) -> None:
        assert ISO_13482_SUITE.adversarial_count >= 15

    def test_all_scenarios_have_required_fields(self) -> None:
        for s in ISO_13482_SUITE.scenarios:
            assert s.id, f"Scenario missing id"
            assert s.name, f"Scenario {s.id} missing name"
            assert s.category == "iso_13482", f"Scenario {s.id} wrong category"
            assert s.description, f"Scenario {s.id} missing description"
            assert s.action, f"Scenario {s.id} missing action"
            assert s.resource, f"Scenario {s.id} missing resource"
            assert s.expected_effect in ("allow", "deny", "allow_with_requirements"), (
                f"Scenario {s.id} has invalid effect: {s.expected_effect}"
            )
            assert s.severity in ("low", "medium", "high", "critical"), (
                f"Scenario {s.id} has invalid severity: {s.severity}"
            )

    def test_actions_use_robotics_taxonomy(self) -> None:
        """All actions should use the robotics action taxonomy."""
        valid_prefixes = ("motion.", "force.", "perception.", "power.", "environment.", "communication.")
        for s in ISO_13482_SUITE.scenarios:
            assert any(s.action.startswith(p) for p in valid_prefixes), (
                f"Scenario {s.id} action '{s.action}' doesn't use robotics taxonomy"
            )

    def test_unique_ids(self) -> None:
        ids = [s.id for s in ISO_13482_SUITE.scenarios]
        assert len(ids) == len(set(ids)), "Duplicate scenario IDs found"

    def test_critical_severity_for_force_limits(self) -> None:
        """Human contact force violations should be critical severity."""
        contact_force = [
            s for s in ISO_13482_SUITE.scenarios
            if "force.contact" in s.action and s.expected_effect == "deny"
        ]
        assert len(contact_force) >= 3
        for s in contact_force:
            assert s.severity == "critical", (
                f"Contact force violation {s.id} should be critical, got {s.severity}"
            )

    def test_critical_severity_for_estop(self) -> None:
        """Emergency stop violations should be critical severity."""
        estop_scenarios = [
            s for s in ISO_13482_SUITE.scenarios
            if "e-stop" in s.tags or "emergency_stop" in s.action
        ]
        for s in estop_scenarios:
            if s.expected_effect == "deny":
                assert s.severity == "critical"

    def test_critical_severity_for_sensor_failure(self) -> None:
        """Continuing after sensor failure should be critical."""
        sensor_fail = [
            s for s in ISO_13482_SUITE.scenarios
            if "sensor" in s.tags and s.expected_effect == "deny"
            and "fail" in s.description.lower()
        ]
        assert len(sensor_fail) >= 1
        for s in sensor_fail:
            assert s.severity == "critical"

    def test_privacy_scenarios_present(self) -> None:
        """Suite includes privacy/data protection scenarios."""
        privacy = [s for s in ISO_13482_SUITE.scenarios if "privacy" in s.tags]
        assert len(privacy) >= 2

    def test_healthcare_scenarios_present(self) -> None:
        """Suite includes healthcare-specific scenarios."""
        healthcare = [s for s in ISO_13482_SUITE.scenarios if "healthcare" in s.tags]
        assert len(healthcare) >= 3
