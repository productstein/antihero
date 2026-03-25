"""Agent Plan Graph — trajectory-level alignment.

An APG represents a multi-step plan before execution begins, allowing
pre-vetting of entire trajectories rather than individual actions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from antihero._internal.time import utcnow


class PlanNode(BaseModel):
    """A single step in an agent's planned trajectory."""

    model_config = ConfigDict(frozen=True)

    node_id: str = Field(..., description="Unique ID within this plan")
    action: str = Field(..., description="Intended tool/action name")
    resource: str = Field(..., description="Intended target")
    parameters: dict[str, Any] = Field(default_factory=dict)
    depends_on: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Node IDs that must complete first",
    )
    risk_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = Field(default="", description="Agent's stated reason for this step")


class PlanEdge(BaseModel):
    """Dependency edge in the plan graph."""

    model_config = ConfigDict(frozen=True)

    from_node: str
    to_node: str
    edge_type: Literal["depends_on", "fallback", "parallel"] = "depends_on"


class AgentPlanGraph(BaseModel):
    """Directed acyclic graph of intended actions.

    Submitted before execution for trajectory-level vetting.
    Enables "approval on plan" rather than per-step approval.
    """

    model_config = ConfigDict(frozen=True)

    envelope_type: Literal["apg"] = "apg"
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utcnow)
    agent_id: str
    session_id: str | None = None
    nodes: tuple[PlanNode, ...] = Field(..., min_length=1)
    edges: tuple[PlanEdge, ...] = Field(default_factory=tuple)
    total_risk_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    plan_approved: bool | None = Field(
        default=None,
        description="Set by policy engine after evaluation",
    )
    rejected_nodes: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Node IDs that were rejected by policy",
    )
