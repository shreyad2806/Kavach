from datetime import datetime, timezone
from enum import Enum
import logging
import os
from pathlib import Path
import uuid
from pydantic import BaseModel, ConfigDict, Field

from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    AuthorizationResult,
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId
from kavach_logger import get_logger

_audit_log = get_logger("kavach.audit")


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


# ============================================================================
# Audit Log Sink & Helper Functions
# ============================================================================


def create_authorization_decision_event(
    request: ActionRequest,
    result: AuthorizationResult,
    event_id: str | None = None,
    timestamp: datetime | None = None,
) -> SecurityEvent:
    """
    Construct an AUTHORIZATION_DECISION SecurityEvent from an ActionRequest and AuthorizationResult.

    Parameters:
        request: ActionRequest evaluated by Kavach.
        result: AuthorizationResult produced by authorize().
        event_id: Optional explicit event_id (generates unique UUID if None).
        timestamp: Optional explicit UTC timestamp (defaults to current UTC time).

    Returns:
        Structured SecurityEvent representing the authorization decision.
    """
    return SecurityEvent(
        event_id=event_id or f"evt-{uuid.uuid4()}",
        timestamp=timestamp or datetime.now(timezone.utc),
        event_type=EventType.AUTHORIZATION_DECISION,
        source_agent=request.source_agent,
        target_agent=request.target_agent,
        request_id=request.request_id,
        task_id=request.task_id,
        action=request.action,
        resource=request.resource,
        policy_decision=result.decision,
        reason_codes=list(result.reason_codes),
        risk_score=result.risk_score,
    )


def write_event(
    event: SecurityEvent,
    log_path: Path | str | None = None,
) -> None:
    """
    Emit a single SecurityEvent to the centralized audit logger.

    log_path is accepted for backward compatibility with tests that inject
    a custom path, but is ignored — the centralized logger owns the file.
    """
    level = (
        logging.WARNING
        if event.policy_decision == AuthorizationDecision.DENY
        else logging.INFO
    )
    _audit_log.log(
        level,
        "authorization_decision",
        extra={
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "source_agent": event.source_agent.value,
            "target_agent": event.target_agent.value,
            "request_id": event.request_id,
            "task_id": event.task_id,
            "action": event.action.value,
            "resource": event.resource.value,
            "policy_decision": event.policy_decision.value,
            "reason_codes": [rc.value for rc in event.reason_codes],
            "risk_score": event.risk_score,
        },
    )
