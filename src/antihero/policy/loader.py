"""Load and merge YAML policy files from a directory."""

from __future__ import annotations

from pathlib import Path

import yaml

from antihero.exceptions import PolicyLoadError, PolicyValidationError
from antihero.policy.schema import PolicyDocument


def load_policies(policy_dir: str | Path | None = None) -> list[PolicyDocument]:
    """Load all policy YAML files from a directory, plus the built-in baseline.

    The baseline policy is always loaded first. Additional policies from the
    directory are layered on top.

    Args:
        policy_dir: Path to directory containing .yaml policy files.
                    If None, only the baseline is loaded.

    Returns:
        List of PolicyDocument objects, sorted by tier order.
    """
    policies: list[PolicyDocument] = []

    # Always load the built-in baseline
    baseline = _load_builtin_baseline()
    policies.append(baseline)

    # Load user-provided policies
    if policy_dir is not None:
        dir_path = Path(policy_dir)
        if dir_path.is_dir():
            for yaml_file in sorted(dir_path.glob("*.yaml")):
                if yaml_file.name == "baseline.yaml":
                    continue  # Don't double-load baseline
                doc = load_policy_file(yaml_file)
                policies.append(doc)

    return policies


def load_policy_file(path: Path) -> PolicyDocument:
    """Load and validate a single YAML policy file.

    Args:
        path: Path to the YAML file.

    Returns:
        Validated PolicyDocument.

    Raises:
        PolicyLoadError: If the file cannot be read or parsed.
        PolicyValidationError: If the content doesn't match the schema.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"Cannot read policy file: {path}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyLoadError(f"Policy file must contain a YAML mapping: {path}")

    try:
        return PolicyDocument.model_validate(data)
    except Exception as exc:
        raise PolicyValidationError(f"Schema validation failed for {path}: {exc}") from exc


def _load_builtin_baseline() -> PolicyDocument:
    """Load the built-in baseline policy from the package."""
    baseline_path = Path(__file__).parent / "defaults" / "baseline.yaml"
    if not baseline_path.exists():
        raise PolicyLoadError("Built-in baseline.yaml not found")
    return load_policy_file(baseline_path)
