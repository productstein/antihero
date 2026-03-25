"""MuJoCo simulation backend for digital twin validation.

Loads an MJCF/URDF model, clones the current state, applies the proposed
action, and checks for safety violations (contact forces, joint efforts,
velocity limits, unexpected collisions).

Requires: pip install antihero[robotics]  (installs mujoco)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from antihero.simulation.digital_twin.config import SimulationConfig
from antihero.simulation.digital_twin.result import SimulationResult, Violation

logger = logging.getLogger(__name__)

# Cache loaded models to avoid re-parsing MJCF on every validation
_model_cache: dict[str, Any] = {}


def _get_mujoco() -> Any:
    """Import mujoco lazily — optional dependency."""
    try:
        import mujoco
        return mujoco
    except ImportError:
        raise ImportError(
            "MuJoCo is required for digital twin validation. "
            "Install with: pip install antihero[robotics]"
        )


def _load_model(model_path: str) -> tuple[Any, Any]:
    """Load and cache an MJCF/URDF model."""
    mj = _get_mujoco()

    if model_path in _model_cache:
        model = _model_cache[model_path]
    else:
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        if path.suffix in (".xml", ".mjcf"):
            model = mj.MjModel.from_xml_path(str(path))
        elif path.suffix == ".urdf":
            model = mj.MjModel.from_xml_path(str(path))
        else:
            raise ValueError(f"Unsupported model format: {path.suffix}")

        _model_cache[model_path] = model

    # Create fresh data (cheap clone)
    data = mj.MjData(model)
    return model, data


def validate(
    config: SimulationConfig,
    action_params: dict[str, Any] | None = None,
) -> SimulationResult:
    """Run simulation validation against the MuJoCo model.

    Steps the simulation forward for `horizon_steps` steps and checks:
    1. Contact forces don't exceed max_contact_force
    2. Joint efforts don't exceed max_joint_effort (% of limit)
    3. Velocities don't exceed max_velocity
    4. No unexpected collisions (bodies not in collision_whitelist)

    Args:
        config: Simulation configuration with thresholds.
        action_params: Optional action parameters (joint targets, forces).

    Returns:
        SimulationResult with safe=True/False and any violations.
    """
    mj = _get_mujoco()
    model, data = _load_model(config.model_path)

    # Apply action parameters if provided
    if action_params:
        _apply_action(model, data, action_params)

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

        mj.mj_step(model, data)
        steps_completed += 1

        # Check contacts
        for i in range(data.ncon):
            contact = data.contact[i]
            force = float(data.efc_force[contact.efc_address]) if contact.efc_address >= 0 else 0.0
            abs_force = abs(force)

            # Get body names for collision checking
            geom1_body = mj.mj_name2id(model, mj.mjtObj.mjOBJ_BODY,
                                        mj.mj_id2name(model, mj.mjtObj.mjOBJ_GEOM, contact.geom1) or "")
            geom2_body = mj.mj_name2id(model, mj.mjtObj.mjOBJ_BODY,
                                        mj.mj_id2name(model, mj.mjtObj.mjOBJ_GEOM, contact.geom2) or "")
            body1_name = mj.mj_id2name(model, mj.mjtObj.mjOBJ_BODY, geom1_body) or f"body{geom1_body}"
            body2_name = mj.mj_id2name(model, mj.mjtObj.mjOBJ_BODY, geom2_body) or f"body{geom2_body}"

            total_contacts += 1
            max_contact_force = max(max_contact_force, abs_force)

            # Check force limit
            if abs_force > config.max_contact_force:
                violations.append(Violation(
                    type="contact_force",
                    description=f"Contact force {abs_force:.1f}N exceeds limit {config.max_contact_force:.1f}N",
                    value=abs_force,
                    limit=config.max_contact_force,
                    step=step,
                    body=f"{body1_name}<->{body2_name}",
                ))

            # Check collision whitelist
            if body1_name not in whitelist_set and body2_name not in whitelist_set:
                violations.append(Violation(
                    type="collision",
                    description=f"Unexpected collision between '{body1_name}' and '{body2_name}'",
                    value=abs_force,
                    limit=0.0,
                    step=step,
                    body=f"{body1_name}<->{body2_name}",
                ))

        # Check joint efforts
        if model.nu > 0:
            for j in range(model.nu):
                effort = abs(float(data.qfrc_actuator[j]))
                limit = float(model.actuator_forcerange[j][1]) if model.actuator_forcerange[j][1] > 0 else 100.0
                effort_pct = (effort / limit) * 100.0
                max_effort_pct = max(max_effort_pct, effort_pct)

                if effort_pct > config.max_joint_effort:
                    violations.append(Violation(
                        type="joint_effort",
                        description=f"Joint {j} effort {effort_pct:.1f}% exceeds limit {config.max_joint_effort:.1f}%",
                        value=effort_pct,
                        limit=config.max_joint_effort,
                        step=step,
                    ))

        # Check velocity
        for j in range(model.nv):
            vel = abs(float(data.qvel[j]))
            max_velocity = max(max_velocity, vel)

            if vel > config.max_velocity:
                violations.append(Violation(
                    type="velocity",
                    description=f"Joint {j} velocity {vel:.2f} m/s exceeds limit {config.max_velocity:.2f} m/s",
                    value=vel,
                    limit=config.max_velocity,
                    step=step,
                ))

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
        engine="mujoco",
    )


def _apply_action(model: Any, data: Any, params: dict[str, Any]) -> None:
    """Apply action parameters to the simulation state.

    Supports:
    - joint_targets: dict of joint_name → target position
    - ctrl: list of control values (direct actuator input)
    - qpos: dict of joint_name → position (set initial state)
    """
    mj = _get_mujoco()

    if "ctrl" in params:
        ctrl = params["ctrl"]
        for i, val in enumerate(ctrl):
            if i < model.nu:
                data.ctrl[i] = float(val)

    if "joint_targets" in params:
        for joint_name, target in params["joint_targets"].items():
            joint_id = mj.mj_name2id(model, mj.mjtObj.mjOBJ_JOINT, joint_name)
            if joint_id >= 0:
                addr = model.jnt_qposadr[joint_id]
                data.qpos[addr] = float(target)

    if "qpos" in params:
        for joint_name, pos in params["qpos"].items():
            joint_id = mj.mj_name2id(model, mj.mjtObj.mjOBJ_JOINT, joint_name)
            if joint_id >= 0:
                addr = model.jnt_qposadr[joint_id]
                data.qpos[addr] = float(pos)
