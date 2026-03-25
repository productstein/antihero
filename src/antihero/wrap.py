"""High-level wrap() API — the simplest way to use Antihero.

    from antihero import wrap
    protected = wrap(my_function)
    result = protected(arg1=val1)
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from antihero.adapters.generic import GenericAdapter
from antihero.evidence.chain import HashChain
from antihero.evidence.store import AuditStore
from antihero.guard import Guard
from antihero.policy.engine import PolicyEngine
from antihero.policy.loader import load_policies


def wrap(
    agent: Any,
    *,
    policy_dir: str | Path | None = None,
    risk_threshold: float = 1.0,
    audit_path: str | Path | None = None,
    confirm_callback: Callable[[str], bool] | None = None,
) -> Any:
    """Wrap an agent or callable with Antihero policy enforcement.

    This is the primary entry point for the SDK. It detects the agent type,
    loads policies, and returns a wrapped version that enforces safety.

    Args:
        agent: The callable, tool, or agent to wrap.
        policy_dir: Directory containing YAML policy files.
                   Defaults to ".antihero" in the current directory.
        risk_threshold: Maximum cumulative risk before denying actions.
        audit_path: Path to the JSONL audit file.
                   Defaults to "{policy_dir}/audit.jsonl".
        confirm_callback: Optional callback for user confirmations.
                         Signature: (message: str) -> bool

    Returns:
        A wrapped version of the agent with policy enforcement.
    """
    # Resolve paths
    if policy_dir is None:
        policy_dir = Path(os.getcwd()) / ".antihero"
    policy_dir = Path(policy_dir)

    if audit_path is None:
        audit_path = policy_dir / "audit.jsonl"

    # Build components
    policies = load_policies(policy_dir if policy_dir.exists() else None)
    engine = PolicyEngine(policies, risk_threshold=risk_threshold)
    chain = HashChain()
    store = AuditStore(audit_path)

    guard = Guard(
        engine=engine,
        chain=chain,
        store=store,
        confirm_callback=confirm_callback,
    )

    # Detect adapter and wrap
    adapter = GenericAdapter()
    if adapter.detect(agent):
        return adapter.wrap(agent, guard)

    raise TypeError(
        f"Cannot wrap object of type {type(agent).__name__}. "
        "Expected a callable or supported agent framework."
    )
