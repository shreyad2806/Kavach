"""
Incident models — data contracts for security incidents.
"""

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

from kavach.gateway.models import ReasonCode
from kavach.identity.models import AgentId


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(..., min_length=1)
    timestamp: datetime = Field(...)
    agent_id: AgentId = Field(...)
    severity: IncidentSeverity = Field(...)
    status: IncidentStatus = Field(default=IncidentStatus.OPEN)
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    request_ids: list[str] = Field(default_factory=list)
    description: str = Field(default="")
