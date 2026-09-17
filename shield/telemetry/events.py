from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

from kavach.gateway.models import ActionName, AuthorizationDecision, ReasonCode, ResourceName
from kavach.identity.models import AgentId


class EventType(str, Enum):
    AUTHORIZATION_REQUEST = "AUTHORIZATION_REQUEST"
    AUTHORIZATION_DECISION = "AUTHORIZATION_DECISION"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    QUARANTINE = "QUARANTINE"


class SecurityEvent(BaseModel):
    """
    Structured security telemetry event contract.
    Captures security-relevant request lifecycle and enforcement events.
    Data contract only; does not implement transport or publishing.
    """
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(
        ...,
        min_length=1,
        description="Unique telemetry event identifier."
    )
    timestamp: datetime = Field(
        ...,
        description="UTC ISO 8601 event generation timestamp."
    )
    event_type: EventType = Field(
        ...,
        description="Constrained security event category."
    )
    source_agent: AgentId = Field(
        ...,
        description="Originating source agent identity."
    )
    target_agent: AgentId = Field(
        ...,
        description="Target recipient agent or tool handler identity."
    )
    request_id: str = Field(
        ...,
        min_length=1,
        description="Associated ActionRequest identifier."
    )
    task_id: str = Field(
        ...,
        min_length=1,
        description="Associated workflow task identifier."
    )
    action: ActionName = Field(
        ...,
        description="Requested action."
    )
    resource: ResourceName = Field(
        ...,
        description="Target resource."
    )
    policy_decision: AuthorizationDecision = Field(
        ...,
        description="Deterministic authorization verdict (ALLOW | DENY)."
    )
    reason_codes: list[ReasonCode] = Field(
        default_factory=list,
        description="List of reason codes associated with this event."
    )
    risk_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Advisory risk score (0-100)."
    )
