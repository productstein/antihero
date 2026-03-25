"""Tool Call Envelope — the input to the policy engine.

A TCE captures everything needed to evaluate whether an action should proceed:
who is requesting it, what they want to do, and the context around the request.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from antihero._internal.time import utcnow


class PrincipalIdentity(BaseModel):
    """Verified human identity behind an agent — Layer 1 of the trust stack.

    Binds agent actions to a cryptographically verified human principal.
    Not "which API key" but "which person, proven."
    """

    model_config = ConfigDict(frozen=True)

    human_id: str = Field(..., description="Verified human identifier (email, sub claim)")
    verified_via: str = Field(
        default="api_key",
        description="Verification method: oauth | passkey | saml | api_key",
    )
    delegation_chain: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Chain from human → agent → sub-agent",
    )
    delegation_token_hash: str | None = Field(
        default=None,
        description="SHA-256 of the delegation/OAuth token",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional identity claims (org, team, scopes)",
    )


class Subject(BaseModel):
    """Who is requesting the action."""

    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(..., description="Unique identifier of the AI agent")
    user_id: str | None = Field(default=None, description="Human user, if known")
    session_id: str | None = Field(default=None, description="Session or conversation ID")
    roles: frozenset[str] = Field(
        default_factory=frozenset,
        description="Roles assigned to this subject",
    )
    parent_agent_id: str | None = Field(
        default=None,
        description="If delegated, the parent agent's ID",
    )
    delegation_depth: int = Field(
        default=0,
        ge=0,
        description="How many delegation hops from the original agent",
    )
    delegated_roles: frozenset[str] = Field(
        default_factory=frozenset,
        description="Roles inherited from parent, attenuated by intersection",
    )
    principal: PrincipalIdentity | None = Field(
        default=None,
        description="Verified human identity behind this agent (Layer 1 trust)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Extension point for org-specific attributes",
    )


class Caller(BaseModel):
    """How the tool call was invoked — direct (model-driven) or programmatic (code sandbox).

    Maps to Anthropic's PTC caller context. Enables policies that distinguish
    between model-deliberated calls and code-sandbox-driven loops.
    """

    model_config = ConfigDict(frozen=True)

    type: str = Field(
        ...,
        description="Invocation context: 'direct' | 'programmatic' | 'mcp' | 'browser' | 'cli'",
    )
    container_id: str | None = Field(
        default=None,
        description="PTC sandbox container ID (scopes risk budgets)",
    )
    tool_id: str | None = Field(
        default=None,
        description="Identifier of the tool/code_execution block that invoked this call",
    )
    sandbox_ttl_seconds: int | None = Field(
        default=None,
        description="Remaining sandbox lifetime in seconds",
    )


class ToolCallEnvelope(BaseModel):
    """Immutable description of an intended tool invocation.

    Created by an adapter before the tool executes. This is the universal
    input contract that every integration surface (SDK, CLI, MCP, browser
    extension) produces.
    """

    model_config = ConfigDict(frozen=True)

    envelope_type: Literal["tce"] = "tce"
    id: UUID = Field(default_factory=uuid4, description="Unique envelope ID")
    timestamp: datetime = Field(default_factory=utcnow, description="When the call was requested")
    subject: Subject
    action: str = Field(..., description="Canonical action name, e.g. 'file.write', 'web.fetch'")
    resource: str = Field(..., description="Target of the action, e.g. file path, URL")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments to the tool call",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context: conversation snippet, risk signals, environment",
    )
    caller: Caller | None = Field(
        default=None,
        description="How this call was invoked (direct, programmatic, mcp, etc.)",
    )
    plan_node_id: str | None = Field(
        default=None,
        description="If part of an APG, which node this corresponds to",
    )
