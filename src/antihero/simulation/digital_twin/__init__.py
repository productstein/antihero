"""Digital twin integration for sim-before-execute safety validation.

Validates physical robot actions in simulation (MuJoCo/Isaac) before
allowing execution on real hardware. Integrates as a policy requirement
kind: 'simulate'.

Usage:
    from antihero.simulation.digital_twin import SimulationValidator

    validator = SimulationValidator()
    result = validator.validate(config, action_params)
    if not result.safe:
        print(f"Blocked: {result.violations}")
"""

from antihero.simulation.digital_twin.config import SimulationConfig
from antihero.simulation.digital_twin.result import SimulationResult, Violation
from antihero.simulation.digital_twin.validator import SimulationValidator

__all__ = [
    "SimulationConfig",
    "SimulationResult",
    "SimulationValidator",
    "Violation",
]
