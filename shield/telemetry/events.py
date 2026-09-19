from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
from pathlib import Path
import threading
import uuid
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    AuthorizationResult,
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.telemetry.context import get_current_workflow_id
from shield.telemetry.session import record_event as _record_session_event
from kavach_logger import get_logger

_audit_log = get_logger("kavach.audit")

# Serializes append writes so concurrent agents cannot interleave a JSONL line.
_write_lock = threading.Lock()


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
    capability: CapabilityName | None = Field(
        default=None,
        description="Capability the source agent presented for this request."
    )
    workflow_id: str | None = Field(
        default=None,
        description="Supervisor workflow this decision belongs to, when applicable."
    )
    checks: dict[str, str] | None = Field(
        default=None,
        description="Per-stage AuthorizationChecks outcome for this decision."
    )


# ============================================================================
# Audit Log Sink & Helper Functions
# ============================================================================

# Kavach-owned audit sink, kept under a Kavach-only directory so the security
# audit trail can never be confused with another subsystem's log file.
DEFAULT_AUDIT_LOG_PATH = (
    Path(__file__).resolve().parent.parent.parent / "logs" / "kavach" / "audit.log"
)


def get_audit_log_path() -> Path:
    """Return the configured audit log path (compatibility stub)."""
    env_path = os.environ.get("KAVACH_AUDIT_LOG_PATH")
    return Path(env_path) if env_path else DEFAULT_AUDIT_LOG_PATH


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
        capability=request.capability,
        workflow_id=get_current_workflow_id(),
        checks={
            name: status
            for name, status in result.checks.model_dump(mode="json").items()
        },
    )


def event_payload(event: SecurityEvent) -> dict[str, Any]:
    """
    Flatten a SecurityEvent into the machine-readable audit record.

    This is the exact object written to the JSONL audit sink and exposed by
    the read APIs — a projection of the SecurityEvent contract, not a second
    event model.
    """
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type.value,
        "category": "authorization",
        "source_agent": event.source_agent.value,
        "target_agent": event.target_agent.value,
        "request_id": event.request_id,
        "task_id": event.task_id,
        "workflow_id": event.workflow_id,
        "action": event.action.value,
        "resource": event.resource.value,
        "capability": event.capability.value if event.capability else None,
        "policy_decision": event.policy_decision.value,
        "reason_codes": [rc.value for rc in event.reason_codes],
        "risk_score": event.risk_score,
        "checks": event.checks,
    }


def write_event(
    event: SecurityEvent,
    log_path: Path | str | None = None,
) -> None:
    """
    Emit exactly one SecurityEvent to the Kavach audit sinks.

    Three sinks, all best-effort and independent of each other:
      1. the append-only JSONL audit file (one complete JSON object per line)
      2. the current-session in-memory buffer (read APIs / dashboard)
      3. the centralized ``kavach.audit`` structured logger

    Telemetry is an audit side effect, never an authorization gate, so a
    failure in any sink is contained here and can never change a verdict.
    """
    payload = event_payload(event)

    path = Path(log_path) if log_path is not None else get_audit_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, default=str)
        with _write_lock:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Failed to append audit record to %s: %s", path, exc
        )

    try:
        _record_session_event(payload)
    except Exception as exc:  # pragma: no cover - defensive
        logging.getLogger(__name__).warning("Failed to record session event: %s", exc)

    level = (
        logging.WARNING
        if event.policy_decision == AuthorizationDecision.DENY
        else logging.INFO
    )
    _audit_log.log(
        level,
        "authorization_decision",
        extra={
            "event_id": payload["event_id"],
            "event_type": payload["event_type"],
            "workflow_id": payload["workflow_id"],
            "source_agent": payload["source_agent"],
            "target_agent": payload["target_agent"],
            "request_id": payload["request_id"],
            "task_id": payload["task_id"],
            "action": payload["action"],
            "resource": payload["resource"],
            "policy_decision": payload["policy_decision"],
            "reason_codes": payload["reason_codes"],
            "risk_score": payload["risk_score"],
        },
    )
