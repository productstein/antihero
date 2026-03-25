"""Simulation validation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class Violation:
    """A single safety violation detected during simulation."""

    type: str  # "contact_force", "joint_effort", "velocity", "collision"
    description: str
    value: float
    limit: float
    step: int  # Simulation step where violation occurred
    body: str = ""  # Body name involved (if applicable)


@dataclass(slots=True)
class SimulationResult:
    """Result of a sim-before-execute validation."""

    safe: bool
    violations: list[Violation] = field(default_factory=list)
    max_contact_force: float = 0.0
    max_joint_effort_pct: float = 0.0
    max_velocity: float = 0.0
    total_contacts: int = 0
    sim_steps_completed: int = 0
    sim_time_ms: float = 0.0
    engine: str = "mujoco"

    def to_dict(self) -> dict[str, Any]:
        """Serialize for audit trail logging."""
        return {
            "safe": self.safe,
            "violations": [
                {
                    "type": v.type,
                    "description": v.description,
                    "value": v.value,
                    "limit": v.limit,
                    "step": v.step,
                    "body": v.body,
                }
                for v in self.violations
            ],
            "max_contact_force": self.max_contact_force,
            "max_joint_effort_pct": self.max_joint_effort_pct,
            "max_velocity": self.max_velocity,
            "total_contacts": self.total_contacts,
            "sim_steps_completed": self.sim_steps_completed,
            "sim_time_ms": self.sim_time_ms,
            "engine": self.engine,
        }

    @property
    def summary(self) -> str:
        """Human-readable summary."""
        if self.safe:
            return (
                f"SAFE: {self.sim_steps_completed} steps, "
                f"max force {self.max_contact_force:.1f}N, "
                f"max effort {self.max_joint_effort_pct:.1f}%, "
                f"sim time {self.sim_time_ms:.1f}ms"
            )
        violation_types = {v.type for v in self.violations}
        return (
            f"UNSAFE: {len(self.violations)} violation(s) "
            f"[{', '.join(violation_types)}] "
            f"at step {self.violations[0].step if self.violations else '?'}"
        )
