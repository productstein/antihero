"""Configuration for simulation validation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SimulationConfig(BaseModel):
    """Configuration for a sim-before-execute validation.

    Extracted from the 'simulate' requirement params in a policy rule.
    """

    model_config = ConfigDict(frozen=True)

    engine: str = Field(
        default="mujoco",
        description="Simulation engine: 'mujoco' or 'isaac'",
    )
    model_path: str = Field(
        default="",
        description="Path to MJCF/URDF model file",
    )
    horizon_steps: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Number of simulation steps to run",
    )
    max_contact_force: float = Field(
        default=50.0,
        gt=0.0,
        description="Maximum allowed contact force in Newtons",
    )
    max_joint_effort: float = Field(
        default=80.0,
        gt=0.0,
        le=100.0,
        description="Maximum allowed joint effort as percentage of limit",
    )
    max_velocity: float = Field(
        default=2.0,
        gt=0.0,
        description="Maximum allowed velocity in m/s",
    )
    collision_whitelist: list[str] = Field(
        default_factory=lambda: ["ground"],
        description="Body names whose contacts are allowed (e.g., ground, table)",
    )
    timeout_ms: float = Field(
        default=50.0,
        gt=0.0,
        description="Maximum simulation time in milliseconds",
    )

    @classmethod
    def from_requirement_params(cls, params: dict[str, Any]) -> SimulationConfig:
        """Create from policy requirement params dict."""
        return cls(**{k: v for k, v in params.items() if k in cls.model_fields})
