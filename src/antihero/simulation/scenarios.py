"""Scenario framework for robot certification.

Provides base classes for certification scenarios and suites.
The ISO 13482 suite is included as a baseline. Additional domain-specific
suites are available in Antihero Cloud.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CertificationScenario:
    """A single scenario to evaluate during robot certification."""

    id: str
    name: str
    category: str
    description: str
    action: str
    resource: str
    parameters: dict[str, Any]
    expected_effect: str  # "allow", "deny", "allow_with_requirements"
    severity: str  # "low", "medium", "high", "critical"
    mitre_attack_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    delegation_depth_override: int | None = None
    parent_agent_id: str | None = None
    delegated_roles: tuple[str, ...] = ()
    principal_human_id: str | None = None
    principal_verified_via: str | None = None


@dataclass(frozen=True)
class ScenarioSuite:
    """A collection of scenarios for a specific domain."""

    id: str
    name: str
    domain: str
    description: str
    scenarios: tuple[CertificationScenario, ...]
    version: str = "1.0"

    @property
    def scenario_count(self) -> int:
        return len(self.scenarios)

    @property
    def benign_count(self) -> int:
        return sum(1 for s in self.scenarios if s.expected_effect != "deny")

    @property
    def adversarial_count(self) -> int:
        return sum(1 for s in self.scenarios if s.expected_effect == "deny")


# Registry of available suites
from antihero.simulation.suites.iso_13482 import ISO_13482_SUITE

_SUITE_REGISTRY: dict[str, ScenarioSuite] = {
    s.id: s
    for s in (
        ISO_13482_SUITE,
    )
}


def get_suite(suite_id: str) -> ScenarioSuite | None:
    """Get a scenario suite by ID."""
    return _SUITE_REGISTRY.get(suite_id)


def get_all_suites() -> list[ScenarioSuite]:
    """Get all available scenario suites."""
    return list(_SUITE_REGISTRY.values())


def get_total_scenario_count() -> int:
    """Total number of scenarios across all suites."""
    return sum(s.scenario_count for s in _SUITE_REGISTRY.values())
