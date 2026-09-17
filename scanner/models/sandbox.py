from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SandboxEventType(str, Enum):
    # Network
    NETWORK_CONNECT = "NETWORK_CONNECT"
    DNS_LOOKUP = "DNS_LOOKUP"
    UNEXPECTED_DOWNLOAD = "UNEXPECTED_DOWNLOAD"
    # Filesystem
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    # Process
    PROCESS_SPAWN = "PROCESS_SPAWN"
    SHELL_EXECUTION = "SHELL_EXECUTION"
    # Secrets / privilege
    SECRET_ACCESS = "SECRET_ACCESS"
    ENV_READ = "ENV_READ"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"


class SandboxEvent(BaseModel):
    """
    A single behavioral event observed during dynamic sandbox execution.
    Captured from container stdout/stderr and syscall-level signals.
    """
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(..., min_length=1)
    event_type: SandboxEventType = Field(..., description="Category of observed behavior.")
    detail: str = Field(..., min_length=1, description="What was observed, e.g. destination IP, file path.")
    suspicious: bool = Field(..., description="Whether this event is considered a suspicious signal.")
    timestamp: datetime = Field(..., description="UTC timestamp of the observed event.")


class SandboxReport(BaseModel):
    """
    Aggregated result of dynamic sandbox execution for one artifact.
    """
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(..., min_length=1)
    executed: bool = Field(..., description="Whether the artifact was successfully executed in the sandbox.")
    exit_code: int | None = Field(default=None, description="Container exit code.")
    events: list[SandboxEvent] = Field(default_factory=list, description="All observed behavioral events.")
    suspicious_event_count: int = Field(default=0, description="Count of events flagged as suspicious.")
    execution_error: str | None = Field(default=None, description="Error message if sandbox execution failed.")
    duration_seconds: float | None = Field(default=None, description="How long the sandbox ran.")
    timestamp: datetime = Field(..., description="UTC timestamp when the sandbox run completed.")
