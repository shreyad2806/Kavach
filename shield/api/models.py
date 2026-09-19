"""
Phase 21D API models — clean Pydantic request/response contracts.
Internal dataclasses are not exposed directly.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


# ============================================================================
# Workflow models
# ============================================================================

class CreateWorkflowRequest(BaseModel):
    task: str = Field(..., min_length=1, description="Task description for the workflow")


class WorkflowEventResponse(BaseModel):
    event_id: str
    workflow_id: str
    timestamp: str
    step: str
    status: str
    detail: str = ""


class WorkflowResponse(BaseModel):
    workflow_id: str
    task: str
    status: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    steps_completed: list[str] = Field(default_factory=list)


class WorkflowEventsResponse(BaseModel):
    workflow_id: str
    events: list[WorkflowEventResponse]


# ============================================================================
# Agent models
# ============================================================================

class AgentResponse(BaseModel):
    agent_id: str
    role: str
    state: str


class AgentStateResponse(BaseModel):
    agent_id: str
    state: str


# ============================================================================
# Incident models
# ============================================================================

class IncidentResponse(BaseModel):
    incident_id: str
    timestamp: str
    agent_id: str
    severity: str
    status: str
    reason_codes: list[str] = Field(default_factory=list)
    request_ids: list[str] = Field(default_factory=list)
    description: str = ""


# ============================================================================
# Event models
# ============================================================================

class SecurityEventResponse(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    source_agent: str
    target_agent: str
    request_id: str
    task_id: str
    action: str
    resource: str
    policy_decision: str
    reason_codes: list[str] = Field(default_factory=list)
    risk_score: int | None = None


# ============================================================================
# Dashboard model
# ============================================================================

class DashboardResponse(BaseModel):
    agents: dict[str, int]
    workflows: dict[str, int]
    incidents: dict[str, int]
    events: dict[str, int]


# ============================================================================
# Policy model
# ============================================================================

class PolicyResponse(BaseModel):
    cedar_policies: str
    action_capability_map: dict[str, str]
    note: str = ""
