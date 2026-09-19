"""Workflow lifecycle models for the P1 Workflow Supervisor.

The supervisor owns WORKFLOW LIFECYCLE only.  Security state (identity,
quarantine, incidents, authorization decisions, security events) remains
owned by Shield and is intentionally NOT duplicated here.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class WorkflowStatus(str, Enum):
    """Lifecycle states for a supervised P1 workflow."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class WorkflowEventType(str, Enum):
    """Supervisor lifecycle event types.

    These are supervisor-owned lifecycle telemetry, correlated by
    workflow_id.  Shield authorization events (AuthorizationResult,
    SecurityEvent, incidents) are NOT duplicated here.
    """

    WORKFLOW_CREATED = "WORKFLOW_CREATED"
    WORKFLOW_STARTED = "WORKFLOW_STARTED"
    WORKFLOW_STOP_REQUESTED = "WORKFLOW_STOP_REQUESTED"
    PHASE_STARTED = "PHASE_STARTED"
    PHASE_COMPLETED = "PHASE_COMPLETED"
    WORKFLOW_STOPPED = "WORKFLOW_STOPPED"
    WORKFLOW_COMPLETED = "WORKFLOW_COMPLETED"
    WORKFLOW_FAILED = "WORKFLOW_FAILED"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PhaseRun:
    """One executed phase of the workflow (one agent operation)."""

    agent: str
    status: WorkflowStatus = WorkflowStatus.RUNNING
    started_at: datetime = field(default_factory=_utc_now)
    completed_at: datetime | None = None
    error: str | None = None


@dataclass
class WorkflowEvent:
    """Supervisor lifecycle event, correlated by workflow_id."""

    event_id: str
    workflow_id: str
    event_type: WorkflowEventType
    timestamp: datetime
    agent: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """A supervised P1 workflow instance (process-local, in-memory)."""

    workflow_id: str
    task: str
    status: WorkflowStatus = WorkflowStatus.CREATED
    created_at: datetime = field(default_factory=_utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    current_agent: str | None = None
    phases: list[PhaseRun] = field(default_factory=list)
    events: list[WorkflowEvent] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        """Return a JSON-friendly snapshot of the workflow state."""
        return {
            "workflow_id": self.workflow_id,
            "task": self.task,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_agent": self.current_agent,
            "phases": [
                {
                    "agent": phase.agent,
                    "status": phase.status.value,
                    "started_at": phase.started_at.isoformat(),
                    "completed_at": (
                        phase.completed_at.isoformat() if phase.completed_at else None
                    ),
                    "error": phase.error,
                }
                for phase in self.phases
            ],
            "result": self.result,
            "error": self.error,
        }


@dataclass
class WorkflowSnapshot:
    """Serializable snapshot of a Workflow for HTTP responses."""

    workflow_id: str
    task: str
    status: WorkflowStatus
    created_at: str | None
    started_at: str | None
    completed_at: str | None
    error: str | None
    steps_completed: list[str] = field(default_factory=list)
