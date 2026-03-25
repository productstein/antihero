"""Policy matching logic.

Uses fnmatch for subject/action/resource matching (auditable, simple)
and operator evaluation for conditions (flexible, type-safe).
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any

from antihero.envelopes.tce import PrincipalIdentity, ToolCallEnvelope
from antihero.policy.schema import PolicyCondition, PolicyRule, PrincipalPolicy


def matches_rule(rule: PolicyRule, tce: ToolCallEnvelope) -> bool:
    """Check if a rule matches a TCE. All criteria must match (AND semantics)."""
    return (
        _matches_subjects(rule.subjects, tce)
        and _matches_globs(rule.actions, tce.action)
        and _matches_globs(rule.resources, tce.resource)
        and _all_conditions_met(rule.conditions, tce)
    )


def _matches_subjects(patterns: list[str], tce: ToolCallEnvelope) -> bool:
    """Match against agent_id, roles, user_id, and principal human_id."""
    targets = [tce.subject.agent_id]
    targets.extend(tce.subject.roles)
    if tce.subject.user_id:
        targets.append(tce.subject.user_id)
    if tce.subject.principal:
        targets.append(tce.subject.principal.human_id)
    return _matches_globs(patterns, *targets)


def validate_principal(
    principal: PrincipalIdentity | None,
    policies: list[PrincipalPolicy],
    action: str,
    agent_id: str,
    delegation_depth: int,
) -> tuple[bool, str]:
    """Validate a principal against principal policies.

    Returns (allowed, reason). If no principal policies exist, validation
    passes (opt-in enforcement). If policies exist but no principal is
    provided, validation fails.
    """
    if not policies:
        return True, ""

    if principal is None:
        return False, "Principal policies defined but no principal identity provided"

    # Find matching principal policy
    for policy in policies:
        if not _matches_globs([policy.id], principal.human_id):
            continue

        # Check verification method
        if policy.verification != "any" and principal.verified_via != policy.verification:
            continue

        # Check delegation depth
        if delegation_depth > policy.max_delegation_depth:
            return False, (
                f"Delegation depth {delegation_depth} exceeds max "
                f"{policy.max_delegation_depth} for principal '{principal.human_id}'"
            )

        # Check agent is in allowed list
        if not _matches_globs(policy.allowed_agents, agent_id):
            return False, (
                f"Agent '{agent_id}' not in allowed agents for "
                f"principal '{principal.human_id}'"
            )

        # Check action is within delegation scope
        if not _matches_globs(policy.delegation_scope, action):
            return False, (
                f"Action '{action}' outside delegation scope for "
                f"principal '{principal.human_id}'"
            )

        return True, ""

    return False, f"No matching principal policy for '{principal.human_id}'"


def _matches_globs(patterns: list[str], *targets: str) -> bool:
    """Return True if any pattern matches any target using fnmatch."""
    for pattern in patterns:
        for target in targets:
            if fnmatch(target, pattern):
                return True
    return False


def _all_conditions_met(conditions: list[PolicyCondition], tce: ToolCallEnvelope) -> bool:
    """All conditions must pass (AND semantics)."""
    for cond in conditions:
        actual = _resolve_dot_path(tce, cond.field)
        if not _evaluate_operator(cond.operator, actual, cond.value):
            return False
    return True


def _resolve_dot_path(tce: ToolCallEnvelope, path: str) -> Any:
    """Resolve a dot-separated path against a TCE.

    Supports paths like 'subject.agent_id', 'parameters.command', 'context.risk_score'.
    """
    obj: Any = tce
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif hasattr(obj, part):
            obj = getattr(obj, part)
        else:
            return None
    return obj


def _evaluate_operator(op: str, actual: Any, expected: Any) -> bool:
    """Evaluate a condition operator."""
    if actual is None:
        return op in ("neq", "not_in")

    match op:
        case "eq":
            return bool(actual == expected)
        case "neq":
            return bool(actual != expected)
        case "in":
            return bool(actual in expected)
        case "not_in":
            return bool(actual not in expected)
        case "gt":
            return bool(actual > expected)
        case "gte":
            return bool(actual >= expected)
        case "lt":
            return bool(actual < expected)
        case "lte":
            return bool(actual <= expected)
        case "contains":
            return expected in actual if isinstance(actual, (str, list, set, frozenset)) else False
        case "matches":
            return bool(re.search(str(expected), str(actual)))
        case _:
            return False
