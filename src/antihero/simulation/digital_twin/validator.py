"""SimulationValidator — dispatches to the appropriate simulation backend.

This is the public API for digital twin validation. It receives a
SimulationConfig (extracted from policy requirement params) and
dispatches to MuJoCo or Isaac backends.
"""

from __future__ import annotations

import logging
from typing import Any

from antihero.simulation.digital_twin.config import SimulationConfig
from antihero.simulation.digital_twin.result import SimulationResult, Violation

logger = logging.getLogger(__name__)


class SimulationValidator:
    """Validates robot actions in simulation before physical execution.

    Usage:
        validator = SimulationValidator()
        result = validator.validate(config, action_params)
        if not result.safe:
            # Block physical execution
            for v in result.violations:
                print(f"  {v.type}: {v.description}")
    """

    def validate(
        self,
        config: SimulationConfig,
        action_params: dict[str, Any] | None = None,
    ) -> SimulationResult:
        """Run simulation validation and return result.

        Dispatches to the appropriate backend based on config.engine.
        Returns SimulationResult with safe=True/False.

        On any error, returns unsafe result (fail-closed).
        """
        try:
            return self._dispatch(config, action_params)
        except ImportError as exc:
            logger.warning("Simulation backend unavailable: %s", exc)
            return SimulationResult(
                safe=False,
                violations=[
                    Violation(
                        type="backend_unavailable",
                        description=str(exc),
                        value=0.0,
                        limit=0.0,
                        step=0,
                    )
                ],
                engine=config.engine,
            )
        except Exception as exc:
            logger.error("Simulation validation failed (fail-closed): %s", exc)
            return SimulationResult(
                safe=False,
                violations=[
                    Violation(
                        type="simulation_error",
                        description=f"Simulation failed: {exc}",
                        value=0.0,
                        limit=0.0,
                        step=0,
                    )
                ],
                engine=config.engine,
            )

    def _dispatch(
        self,
        config: SimulationConfig,
        action_params: dict[str, Any] | None,
    ) -> SimulationResult:
        """Dispatch to the correct backend."""
        match config.engine:
            case "mujoco":
                from antihero.simulation.digital_twin import mujoco_backend
                return mujoco_backend.validate(config, action_params)
            case "isaac":
                from antihero.simulation.digital_twin import isaac_backend
                return isaac_backend.validate(config, action_params)
            case _:
                return SimulationResult(
                    safe=False,
                    violations=[
                        Violation(
                            type="unknown_engine",
                            description=f"Unknown simulation engine: {config.engine}",
                            value=0.0,
                            limit=0.0,
                            step=0,
                        )
                    ],
                    engine=config.engine,
                )
