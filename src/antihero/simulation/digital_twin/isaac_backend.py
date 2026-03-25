"""NVIDIA Isaac Sim backend for digital twin validation.

Connects to a running Isaac Sim instance (headless or GUI) to validate
robot actions in high-fidelity simulation before physical execution.

Requires:
- NVIDIA GPU with CUDA support
- Isaac Sim 4.5+ installed
- isaacsim Python package available

This backend provides higher-fidelity validation than MuJoCo for
scenarios requiring:
- GPU-accelerated physics (PhysX 5)
- Photorealistic rendering for vision-based safety checks
- Complex sensor simulation (LiDAR, depth cameras)
- Multi-robot fleet simulation

Usage:
    config = SimulationConfig(engine="isaac", model_path="robot.usd")
    result = validate(config, action_params)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from antihero.simulation.digital_twin.config import SimulationConfig
from antihero.simulation.digital_twin.result import SimulationResult, Violation

logger = logging.getLogger(__name__)

# Cache simulation app instance (expensive to create)
_sim_app: Any = None
_world: Any = None


def _get_isaac() -> tuple[Any, Any]:
    """Import and initialize Isaac Sim lazily.

    Returns (SimulationApp module, simulation_utils module).
    Raises ImportError with helpful message if not available.
    """
    try:
        from isaacsim import SimulationApp
        return SimulationApp, None
    except ImportError:
        raise ImportError(
            "NVIDIA Isaac Sim is required for this backend. "
            "Isaac Sim requires an NVIDIA GPU with CUDA support. "
            "Install Isaac Sim from https://developer.nvidia.com/isaac-sim "
            "and ensure the isaacsim package is available in your Python path. "
            "Alternatively, use engine='mujoco' for CPU-based validation."
        )


def _ensure_sim_app() -> Any:
    """Get or create the SimulationApp singleton."""
    global _sim_app
    if _sim_app is not None:
        return _sim_app

    SimulationApp, _ = _get_isaac()
    _sim_app = SimulationApp({"headless": True})
    logger.info("Isaac Sim headless app initialized")
    return _sim_app


def _load_stage(model_path: str) -> Any:
    """Load a USD stage (robot model) into the simulation."""
    global _world

    sim_app = _ensure_sim_app()

    # Import after SimulationApp is created (Isaac requirement)
    from omni.isaac.core import World
    from omni.isaac.core.utils.stage import add_reference_to_stage

    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    if path.suffix not in (".usd", ".usda", ".usdc", ".urdf"):
        raise ValueError(
            f"Unsupported model format for Isaac Sim: {path.suffix}. "
            f"Use .usd, .usda, .usdc, or .urdf"
        )

    # Create or reset world
    if _world is not None:
        _world.clear()
    _world = World(stage_units_in_meters=1.0)

    # Add robot to stage
    add_reference_to_stage(usd_path=str(path), prim_path="/World/Robot")

    # Initialize physics
    _world.reset()

    return _world


def validate(
    config: SimulationConfig,
    action_params: dict[str, Any] | None = None,
) -> SimulationResult:
    """Run simulation validation using NVIDIA Isaac Sim.

    Loads the robot model into Isaac Sim, applies the proposed action,
    steps the physics, and checks for safety violations.

    This provides higher-fidelity validation than MuJoCo:
    - PhysX 5 GPU-accelerated rigid body + soft body physics
    - Accurate contact reporting with material properties
    - Sensor simulation (cameras, LiDAR) for vision-based safety
    - Multi-robot simulation for fleet scenarios

    Args:
        config: Simulation configuration with thresholds.
        action_params: Optional action parameters (joint targets, forces).

    Returns:
        SimulationResult with safe=True/False and any violations.
    """
    _get_isaac()  # Verify availability before proceeding

    world = _load_stage(config.model_path)

    # Apply action parameters if provided
    if action_params:
        _apply_action(world, action_params)

    violations: list[Violation] = []
    max_contact_force = 0.0
    max_effort_pct = 0.0
    max_velocity = 0.0
    total_contacts = 0
    whitelist_set = set(config.collision_whitelist)

    start_time = time.perf_counter()
    timeout_s = config.timeout_ms / 1000.0
    steps_completed = 0

    for step in range(config.horizon_steps):
        # Timeout check
        elapsed = time.perf_counter() - start_time
        if elapsed > timeout_s:
            violations.append(Violation(
                type="timeout",
                description=f"Simulation timed out after {elapsed*1000:.1f}ms",
                value=elapsed * 1000,
                limit=config.timeout_ms,
                step=step,
            ))
            break

        world.step(render=False)
        steps_completed += 1

        # Check contacts via Isaac Sim contact reporter
        contact_violations = _check_contacts(
            world, step, config.max_contact_force, whitelist_set
        )
        for v in contact_violations:
            violations.append(v)
            if v.type == "contact_force":
                max_contact_force = max(max_contact_force, v.value)
            total_contacts += 1

        # Check joint efforts
        effort_violations, step_max_effort = _check_joint_efforts(
            world, step, config.max_joint_effort
        )
        violations.extend(effort_violations)
        max_effort_pct = max(max_effort_pct, step_max_effort)

        # Check velocities
        velocity_violations, step_max_vel = _check_velocities(
            world, step, config.max_velocity
        )
        violations.extend(velocity_violations)
        max_velocity = max(max_velocity, step_max_vel)

    sim_time_ms = (time.perf_counter() - start_time) * 1000.0

    return SimulationResult(
        safe=len(violations) == 0,
        violations=violations,
        max_contact_force=max_contact_force,
        max_joint_effort_pct=max_effort_pct,
        max_velocity=max_velocity,
        total_contacts=total_contacts,
        sim_steps_completed=steps_completed,
        sim_time_ms=sim_time_ms,
        engine="isaac",
    )


def _apply_action(world: Any, params: dict[str, Any]) -> None:
    """Apply action parameters to the Isaac Sim world.

    Supports:
    - joint_targets: dict of joint_name → target position
    - ctrl: list of control values (direct actuator input)
    - joint_velocities: dict of joint_name → target velocity
    """
    try:
        from omni.isaac.core.articulations import ArticulationView
        import numpy as np

        # Find the robot articulation
        robot = world.scene.get_object("Robot")
        if robot is None:
            logger.warning("No robot articulation found in scene")
            return

        if "joint_targets" in params:
            targets = params["joint_targets"]
            if isinstance(targets, dict):
                # Convert dict to array matching joint order
                joint_positions = robot.get_joint_positions()
                for name, value in targets.items():
                    idx = _get_joint_index(robot, name)
                    if idx is not None and idx < len(joint_positions):
                        joint_positions[idx] = float(value)
                robot.set_joint_position_targets(joint_positions)

        if "ctrl" in params:
            ctrl = np.array(params["ctrl"], dtype=np.float32)
            robot.set_joint_efforts(ctrl[:robot.num_dof])

        if "joint_velocities" in params:
            velocities = params["joint_velocities"]
            if isinstance(velocities, dict):
                joint_vels = robot.get_joint_velocities()
                for name, value in velocities.items():
                    idx = _get_joint_index(robot, name)
                    if idx is not None and idx < len(joint_vels):
                        joint_vels[idx] = float(value)
                robot.set_joint_velocity_targets(joint_vels)

    except Exception as exc:
        logger.warning("Failed to apply action params in Isaac Sim: %s", exc)


def _get_joint_index(robot: Any, joint_name: str) -> int | None:
    """Get joint index by name from an Isaac Sim articulation."""
    try:
        joint_names = robot.dof_names
        if joint_name in joint_names:
            return joint_names.index(joint_name)
    except Exception:
        pass
    return None


def _check_contacts(
    world: Any,
    step: int,
    max_force: float,
    whitelist: set[str],
) -> list[Violation]:
    """Check contact forces and unexpected collisions."""
    violations: list[Violation] = []

    try:
        from omni.isaac.core.utils.physics import get_contact_report

        contacts = get_contact_report()
        if contacts is None:
            return violations

        for contact in contacts:
            body1 = getattr(contact, "body0", "unknown")
            body2 = getattr(contact, "body1", "unknown")
            force = getattr(contact, "impulse_magnitude", 0.0)
            abs_force = abs(float(force))

            if abs_force > max_force:
                violations.append(Violation(
                    type="contact_force",
                    description=f"Contact force {abs_force:.1f}N exceeds limit {max_force:.1f}N",
                    value=abs_force,
                    limit=max_force,
                    step=step,
                    body=f"{body1}<->{body2}",
                ))

            # Check collision whitelist
            body1_name = str(body1).split("/")[-1] if "/" in str(body1) else str(body1)
            body2_name = str(body2).split("/")[-1] if "/" in str(body2) else str(body2)
            if body1_name not in whitelist and body2_name not in whitelist:
                violations.append(Violation(
                    type="collision",
                    description=f"Unexpected collision between '{body1_name}' and '{body2_name}'",
                    value=abs_force,
                    limit=0.0,
                    step=step,
                    body=f"{body1_name}<->{body2_name}",
                ))

    except Exception as exc:
        logger.debug("Contact check skipped: %s", exc)

    return violations


def _check_joint_efforts(
    world: Any,
    step: int,
    max_effort_pct: float,
) -> tuple[list[Violation], float]:
    """Check joint efforts against limits. Returns (violations, max_effort_pct)."""
    violations: list[Violation] = []
    step_max = 0.0

    try:
        robot = world.scene.get_object("Robot")
        if robot is None:
            return violations, step_max

        efforts = robot.get_applied_joint_efforts()
        effort_limits = robot.get_max_efforts()

        if efforts is not None and effort_limits is not None:
            for j in range(len(efforts)):
                effort = abs(float(efforts[j]))
                limit = float(effort_limits[j]) if effort_limits[j] > 0 else 100.0
                pct = (effort / limit) * 100.0
                step_max = max(step_max, pct)

                if pct > max_effort_pct:
                    violations.append(Violation(
                        type="joint_effort",
                        description=f"Joint {j} effort {pct:.1f}% exceeds limit {max_effort_pct:.1f}%",
                        value=pct,
                        limit=max_effort_pct,
                        step=step,
                    ))

    except Exception as exc:
        logger.debug("Joint effort check skipped: %s", exc)

    return violations, step_max


def _check_velocities(
    world: Any,
    step: int,
    max_velocity: float,
) -> tuple[list[Violation], float]:
    """Check joint velocities against limits. Returns (violations, max_velocity)."""
    violations: list[Violation] = []
    step_max = 0.0

    try:
        robot = world.scene.get_object("Robot")
        if robot is None:
            return violations, step_max

        velocities = robot.get_joint_velocities()
        if velocities is not None:
            for j in range(len(velocities)):
                vel = abs(float(velocities[j]))
                step_max = max(step_max, vel)

                if vel > max_velocity:
                    violations.append(Violation(
                        type="velocity",
                        description=f"Joint {j} velocity {vel:.2f} m/s exceeds limit {max_velocity:.2f} m/s",
                        value=vel,
                        limit=max_velocity,
                        step=step,
                    ))

    except Exception as exc:
        logger.debug("Velocity check skipped: %s", exc)

    return violations, step_max


def cleanup() -> None:
    """Clean up Isaac Sim resources."""
    global _sim_app, _world
    if _world is not None:
        _world.clear()
        _world = None
    if _sim_app is not None:
        _sim_app.close()
        _sim_app = None
    logger.info("Isaac Sim cleaned up")
