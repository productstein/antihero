"""Pydantic models for YAML policy files.

A policy document belongs to one tier (baseline, org, app, user) and contains
an ordered list of rules. Rules match on subject/action/resource patterns and
optional conditions, producing an effect (allow, deny, allow_with_requirements).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class PrincipalPolicy(BaseModel):
    """A principal delegation policy — who can delegate to which agents.

    Defines a verified human identity, what verification method is required,
    which actions the human can delegate to agents, and the maximum delegation
    chain depth.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Principal identifier pattern (email, glob)")
    verification: Literal["oauth", "passkey", "saml", "api_key", "any"] = Field(
        default="any",
        description="Required verification method for this principal",
    )
    delegation_scope: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns of actions this principal may delegate",
    )
    max_delegation_depth: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Maximum delegation chain length (human → agent → sub-agent)",
    )
    allowed_agents: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns of agent_ids this principal may delegate to",
    )


class PolicyCondition(BaseModel):
    """A single condition predicate evaluated against the TCE."""

    model_config = ConfigDict(frozen=True)

    field: str = Field(
        ...,
        description="Dot-path into TCE, e.g. 'subject.roles', 'context.risk_score'",
    )
    operator: Literal[
        "eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte", "contains", "matches"
    ]
    value: Any


class PolicyRule(BaseModel):
    """A single policy rule within a tier."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique rule identifier")
    description: str = ""
    effect: Literal["allow", "deny", "allow_with_requirements"]
    priority: int = Field(
        default=0,
        description="Higher priority rules are evaluated first within a tier",
    )
    subjects: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns for agent_id or role",
    )
    actions: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns for action names",
    )
    resources: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns for resource identifiers",
    )
    conditions: list[PolicyCondition] = Field(default_factory=list)
    requirements: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Required only when effect is allow_with_requirements",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Risk weight assigned when this rule matches",
    )


class PolicyDocument(BaseModel):
    """A complete policy YAML file, belonging to one tier."""

    model_config = ConfigDict(frozen=True)

    version: str = "1.0"
    tier: Literal["baseline", "org", "app", "user"]
    name: str
    description: str = ""
    principals: list[PrincipalPolicy] = Field(
        default_factory=list,
        description="Principal delegation policies — who can delegate what to whom",
    )
    rules: list[PolicyRule] = Field(..., min_length=1)
