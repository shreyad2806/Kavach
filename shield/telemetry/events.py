from datetime import datetime, timezone
from enum import Enum
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

DEFAULT_AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "audit.log"


def get_audit_log_path() -> Path:
    """Return the configured audit log file path."""
    env_path = os.environ.get("KAVACH_AUDIT_LOG_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_AUDIT_LOG_PATH


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
    Append a single SecurityEvent as a JSON line to the audit log.

    Parameters:
        event: SecurityEvent to record.
        log_path: Path to audit log file. Defaults to get_audit_log_path().
    """
    path = Path(log_path) if log_path is not None else get_audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    json_line = event.model_dump_json()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json_line + "\n")
        f.flush()
